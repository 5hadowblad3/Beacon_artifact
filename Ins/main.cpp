#include "deserialize.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Transforms/Scalar.h"
#include "llvm/Transforms/Instrumentation.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Analysis/CallGraph.h"
#include "llvm/Bitcode/BitcodeWriter.h"
#include "llvm/IR/IRPrintingPasses.h"


#include "llvm/ADT/Statistic.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/IR/TypeBuilder.h"

#include "config.h"
#include "debug.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <set>
#include <fstream>
#include <string>
#include <iostream>

#  define AFL_R(x) (random() % (x))


using namespace llvm;

namespace {
    cl::opt<std::string> InputFilename(cl::Positional, cl::desc("<filename>.bc"), cl::init(""));
    cl::opt<std::string>
            TargetFile("target-file",
                       cl::desc("Specify a file for target instructions, used in backward analysis"));

    cl::opt<std::string>
            OutputFile("output",
                       cl::desc("Specify a file for the transformed bc, used in backward analysis and others")
    );

    cl::opt<std::string> TargetPoints(
            "tpoints",
            cl::desc("Input file containing the target points for reproducing the bug."),
            cl::value_desc("filename")
    );

    cl::opt<bool> DoInterprocAnalysis(
            "inter-backward",
            cl::init(true)
    );

    cl::opt<std::string> LoadSummary(
            "load",
            cl::desc("Input file containing the inferred condition for the target point."),
            cl::value_desc("filename")
    );

    cl::opt<std::string> BlockFile(
            "blocks",
            cl::desc("Input file containing the distance of the basic blocks reachable to the provided targets."),
            cl::value_desc("filename")
    );

    cl::opt<std::string> LogFile(
            "log",
            cl::desc("log file for some case"),
            cl::value_desc("filename")
            );

    cl::opt<bool> Quiet (
            "quiet",
            cl::desc("skip inference process"),
            cl::init(false)
    );

    cl::opt<bool> Debug (
            "debug",
            cl::desc("add more debug info"),
            cl::init(false)
    );

    cl::opt<bool> Asan (
            "asan",
            cl::desc("add asan"),
            cl::init(false)
    );

    cl::opt<bool> Afl (
            "afl",
            cl::desc("add afl inst"),
            cl::init(false)
    );

    cl::opt<bool> Source(
            "src",
            cl::desc("Use source code location for indexing"),
            cl::init(false)
            );

    cl::opt<bool> Byte(
            "byte",
            cl::desc("Use LLVM byte code location for indexing"),
            cl::init(false)
            );

    cl::opt<bool> Profile(
            "feedback",
            cl::desc("Inst feedback for fuzzer"),
            cl::init(false)
            );

    std::set<const Instruction *> getTargetInsts(Module &M, const std::string &scopeFile) {
        auto getDSPIPath = [] (const DILocation &Loc) {
            std::string dir = Loc.getDirectory();
            std::string file = Loc.getFilename();
            if (dir.empty() || file[0] == '/') {
                return file;
            } else if (*dir.rbegin() == '/') {
                return dir + file;
            } else {
                return dir + "/" + file;
            }
        };

        std::set<const Instruction *> targets;

        std::ifstream f(scopeFile.c_str(), std::ios::in);
        if (!f.good())
            assert(0 && "unable to open path file");

        std::set<std::pair<std::string, unsigned >> scopeInfo;
        std::string s;
        while (std::getline(f, s)) {
            auto pos = s.find(":");
            assert(pos != std::string::npos);

            std::string fName = s.substr(0, pos);
            std::string line = s.substr(pos + 1);

            scopeInfo.insert({fName, std::stoi(line)});
        }

        for (Module::iterator F = M.begin(), E = M.end(); F != E; ++F) {
            Function *Func = &*F;
            for (inst_iterator I = inst_begin(Func), E = inst_end(Func); I != E; ++I) {
                if (MDNode *N = I->getMetadata("dbg")) {
                    DILocation *Loc = cast<DILocation>(N);
                    std::string File = getDSPIPath(*Loc);
                    unsigned Line = Loc->getLine();
                    std::pair<std::string, unsigned> K = {File, Line};
                    auto eqK = [K](const std::pair<std::string, unsigned> &p) {
                        return p.second == K.second && K.first.find(p.first) != std::string::npos;
                    };

                    if (std::find_if(scopeInfo.begin(), scopeInfo.end(), eqK) != scopeInfo.end()) {
                        if (I->getOpcode() == Instruction::Call) {
                            targets.insert(&*I);
                        }
                    }
                }
            }
        }

        assert(targets.size() == scopeInfo.size());
        return targets;
    }



    static void getDebugLoc(const Instruction *I, std::string &Filename,
                            unsigned &Line) {
#ifdef LLVM_OLD_DEBUG_API
        DebugLoc Loc = I->getDebugLoc();
    if (!Loc.isUnknown()) {
        DILocation cDILoc(Loc.getAsMDNode(M.getContext()));
        DILocation oDILoc = cDILoc.getOrigLocation();

        Line = oDILoc.getLineNumber();
        Filename = oDILoc.getFilename().str();

        if (filename.empty()) {
            Line = cDILoc.getLineNumber();
            Filename = cDILoc.getFilename().str();
        }
    }
#else
        if(I == nullptr || !I->hasMetadata()) {
            return;
        }

        DILocation *Loc = I->getDebugLoc();

        if (Loc) {
            Line = Loc->getLine();
            Filename = Loc->getFilename().str();

            if (Filename.empty()) {
                DILocation *oDILoc = Loc->getInlinedAt();
                if (oDILoc) {
                    Line = oDILoc->getLine();
                    Filename = oDILoc->getFilename().str();
                }
            }
        }

#endif /* LLVM_OLD_DEBUG_API */
    }

}

static std::map<std::string, std::map<std::string, bool>> reachable_blocks;
static std::map<unsigned, bool> reachable_inst;
std::set<const llvm::BasicBlock*> reachable_bb;
class AFLCoverage : public ModulePass {

public:

    static char ID;
    AFLCoverage() : ModulePass(ID) {


    }

    bool runOnModule(Module &M) override;

    void getAnalysisUsage(AnalysisUsage &AU);

};




char AFLCoverage::ID = 0;


bool AFLCoverage::runOnModule(Module &M) {

    std::cout << "prepare precondition inference" << std::endl;
    std::unordered_map<const llvm::Function*, FunctionResult> v_guard;

    /* Instrument all the things! */
    if(!Quiet) {
        if (LoadSummary.empty()) {
            //std::cout << "start inference" << std::endl;
            //auto targets = getTargetInsts(M, TargetFile);
            //WPInferenceInterface condition_inference_engine(&M, targets, DoInterprocAnalysis);
            //condition_inference_engine.run(false);
            //v_guard = condition_inference_engine.getResult();
            //condition_inference_engine.dumpResult();
            //std::cout << "inference finish" << std::endl;
        }
        else {
            std::cout << "start loading" << std::endl;
            v_guard = PersistenceAnalysisData::deserialize(&M, LoadSummary);
            std::cout << "finish loading" << std::endl;
        }
    }

    LLVMContext &C = M.getContext();

    IntegerType *Int1Ty  = IntegerType::getInt1Ty(C);
    IntegerType *Int8Ty  = IntegerType::getInt8Ty(C);
    IntegerType *Int16Ty  = IntegerType::getInt16Ty(C);
    IntegerType *Int32Ty = IntegerType::getInt32Ty(C);
    IntegerType *Int64Ty = IntegerType::getInt64Ty(C);

    /* Show a banner */

    char be_quiet = 0;

    if (isatty(2) && !getenv("AFL_QUIET")) {

        SAYF(cCYA "afl-llvm-pass " cBRI VERSION cRST " by Shadow\n");

    } else be_quiet = 1;

    /* Decide instrumentation ratio */

    char* inst_ratio_str = getenv("AFL_INST_RATIO");
    unsigned int inst_ratio = 100;

    if (inst_ratio_str) {

        if (sscanf(inst_ratio_str, "%u", &inst_ratio) != 1 || !inst_ratio ||
            inst_ratio > 100)
            FATAL("Bad value of AFL_INST_RATIO (must be between 1 and 100)");

    }


#ifdef __x86_64__
    IntegerType *LargestType = Int64Ty;
    ConstantInt *MapCntLoc = ConstantInt::get(LargestType, MAP_SIZE + 8);
    ConstantInt *MapReachLoc = ConstantInt::get(LargestType, MAP_SIZE + 16);
    ConstantInt *MapFilterLoc = ConstantInt::get(LargestType, MAP_SIZE + 24);
#else
    IntegerType *LargestType = Int32Ty;
  ConstantInt *MapCntLoc = ConstantInt::get(LargestType, MAP_SIZE + 4);
  ConstantInt *MapReachLoc = ConstantInt::get(LargestType, MAP_SIZE + 8);
  ConstantInt *MapFilterLoc = ConstantInt::get(LargestType, MAP_SIZE + 12);
#endif
    ConstantInt *MapDistLoc = ConstantInt::get(LargestType, MAP_SIZE);
    ConstantInt *Zero = ConstantInt::get(LargestType, 0);
    ConstantInt *One = ConstantInt::get(LargestType,1);
    ConstantInt *Two = ConstantInt::get(LargestType, 2);

    /* Get globals for the SHM region and the previous location. Note that
       __afl_prev_loc is thread-local. */

    GlobalVariable *AFLMapPtr = M.getGlobalVariable("__afl_area_ptr");
    GlobalVariable *AFLPrevLoc = M.getGlobalVariable("__afl_prev_loc");

    std::cout << "start afl instrumentation" << std::endl;
    if (AFLPrevLoc == nullptr || AFLMapPtr == nullptr) {
        std::cout << "load global pointer" << std::endl;
        AFLMapPtr =
                new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                                   GlobalValue::ExternalLinkage, 0, "__afl_area_ptr");

        AFLPrevLoc = new GlobalVariable(
                M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_loc",
                0, GlobalVariable::GeneralDynamicTLSModel, 0, false);
    }

    auto func = M.getFunction("printf");


    std::cout << v_guard.size() << " functions has guards" << std::endl;

    int inst_blocks = 0;
    int num_inst = 0;
    int num_block = 0;
    int skip_block = 0;
    int null_block = 0;
    int num_function = M.size();
    int pointer_guard = 0;


    std::ifstream cf(BlockFile);
    std::string line;

    //        cf.open(BlockFile);

    if (cf.is_open()) {
        std::cout << "start to load reachable bb " + BlockFile << std::endl;

        if (Source) {
            std::string line;
            while (std::getline(cf, line)) {
                std::cout << line << std::endl;
                auto it = line.find(":");
                auto it2 = line.find("TARGET");
                auto loc = line;
                auto filename = line.substr(0, it);

                if(it2 != std::string::npos) {
                    loc = line.substr( it + 1, it2 - it - 2);
                    std::cout << "find Target: " << filename << " " << loc << std::endl;
                    reachable_blocks[filename][loc] = true;
                }
                else {
                    loc = line.substr( it + 1, std::string::npos);
                    reachable_blocks[filename][loc] = false;
                }
            }
        }
        else {
            reachable_bb = PersistenceAnalysisData::getReachableBBs(&M, BlockFile);
        }

        cf.close();
    }
    std::cout << "num of reachable block: "  << reachable_blocks.size() << std::endl;

    for (auto &F : M) {
        std::string fname = F.getName().str();
        std::cout << "Fname: " << fname << std::endl;

        if(F.isIntrinsic() || F.empty() || F.getName().str().find("_GLOBAL") != std::string::npos) {
            std::cout << "no need to handle, skip " << fname << std::endl;
            continue;
        }

        num_block += F.size();

        std::cout << "Start AFL instrumentation for function: " << fname << std::endl;

        if (Debug) {
            IRBuilder<> temp_builder(&(*F.getEntryBlock().getFirstInsertionPt()));
            std::vector<Value *> printArgs;
            Value *formatStr = temp_builder.CreateGlobalStringPtr("current func: %s\n");
            printArgs.push_back(formatStr);
            printArgs.push_back(temp_builder.CreateGlobalStringPtr(F.getName()));
            temp_builder.CreateCall(func, printArgs);
        }


        for (auto &BB : F) {
            num_inst += BB.size();

            BasicBlock::iterator IP = BB.getFirstInsertionPt();
            IRBuilder<> IRB(&(*IP));


            /* Make up cur_loc */

            if(Afl) {
            unsigned int cur_loc = AFL_R(MAP_SIZE);

            ConstantInt *CurLoc = ConstantInt::get(Int32Ty, cur_loc);

            /* Load prev_loc */

            LoadInst *PrevLoc = IRB.CreateLoad(AFLPrevLoc);
            PrevLoc->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
            Value *PrevLocCasted = IRB.CreateZExt(PrevLoc, IRB.getInt32Ty());

            /* Load SHM pointer */
            LoadInst *MapPtr = IRB.CreateLoad(AFLMapPtr);
            MapPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
            Value* Xor = IRB.CreateXor(PrevLocCasted, CurLoc);
            Value *MapPtrIdx =
                    IRB.CreateGEP(MapPtr, Xor);
        

            /* Update bitmap */

            LoadInst *Counter = IRB.CreateLoad(MapPtrIdx);
            Counter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
            Value *Incr = IRB.CreateAdd(Counter, ConstantInt::get(Int8Ty, 1));
            StoreInst *Store2 = IRB.CreateStore(Incr, MapPtrIdx);
            Store2->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

            /* Set prev_loc to cur_loc >> 1 */

            StoreInst *Store =
                    IRB.CreateStore(ConstantInt::get(Int32Ty, cur_loc >> 1), AFLPrevLoc);
            Store->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

            inst_blocks++;
            }

        }

        std::cout << "Finish AFL instrumentation for function: " << fname << std::endl;

        auto exitF = M.getOrInsertFunction("exit", Type::getVoidTy(C), Int32Ty, NULL);

        // reachability filtration

        if(!BlockFile.empty()
            && fname.find("cxx") == std::string::npos
            && fname.find("2E") == std::string::npos) {

            if(Source) {
                std::string bb_name("");
                std::string filename;
                unsigned line;

                for(auto& BB : F) {
                    bool filter = false;
                    std::cout << "new bb" << std::endl;
                    if(!reachable_bb.empty() && reachable_bb.find(&BB) == reachable_bb.end()) {
                        skip_block++;
                    }
                    for (auto &I : BB) {
                        getDebugLoc(reinterpret_cast<const Instruction *>(&I), filename, line);

                        if (filename.empty() || line == 0) {
                            continue;
                        }

                        std::size_t found = filename.find_last_of("/\\");
                        if (found != std::string::npos)
                            filename = filename.substr(found + 1);

                        auto loc = std::to_string(line);
                        bb_name = filename + ":" + loc;
                        std::cout << "bb_name: " << bb_name << std::endl;
                        //		    I.dump();
                        if (!reachable_blocks.empty()) {
                            if (reachable_blocks[filename].find(loc) == reachable_blocks[filename].end()) {
                                std::cout << "filter!" << std::endl;
                                skip_block++;
                                filter = true;
                                break;
                            }
                            else {
                                std::cout << "preserve!" << std::endl;
                                reachable_bb.insert(&BB);
                                break;
                            }
                        }
                        else{
                            std::cout << "empty????" << std::endl;
                            break;
                        }
                    }

                    if(filter) {

                        IRBuilder<> builder_val(&*(BB.getFirstInsertionPt()));

                        if (Debug) {
                            std::vector<Value *> printArgs;
                            Value *formatStr = builder_val.CreateGlobalStringPtr("current func before exit: %s\n");
                            printArgs.push_back(formatStr);
                            printArgs.push_back(builder_val.CreateGlobalStringPtr(F.getName()));
                            builder_val.CreateCall(func, printArgs);
                        }

                        if (Profile) {
                            LoadInst *MapPtr = builder_val.CreateLoad(AFLMapPtr);
                            Value *MapFilterPtr = builder_val.CreateBitCast(
                                    builder_val.CreateGEP(MapPtr, MapFilterLoc), LargestType->getPointerTo());
                            LoadInst *MapFilter = builder_val.CreateLoad(MapFilterPtr);
                            MapFilter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

                            Value *IncrFilter = builder_val.CreateAdd(MapFilter, Two);
                            builder_val.CreateStore(IncrFilter, MapFilterPtr)
                            ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
                        }

                        builder_val.CreateCall(exitF, ConstantInt::get(Int32Ty, 0))->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
                    }
                }
            }

            if(Byte) {
                for(auto& BB : F) {
                    bool filter = false;
                    if (reachable_bb.find(&BB) == reachable_bb.end()) {
                        IRBuilder<> builder_val(&*(BB.getFirstInsertionPt()));

                        if (Profile) {
                            LoadInst *MapPtr = builder_val.CreateLoad(AFLMapPtr);
                            Value *MapFilterPtr = builder_val.CreateBitCast(
                                    builder_val.CreateGEP(MapPtr, MapFilterLoc), LargestType->getPointerTo());
                            LoadInst *MapFilter = builder_val.CreateLoad(MapFilterPtr);
                            MapFilter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

                            Value *IncrFilter = builder_val.CreateAdd(MapFilter, Two);
                            builder_val.CreateStore(IncrFilter, MapFilterPtr)
                            ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
                        }

                        builder_val.CreateCall(exitF, ConstantInt::get(Int32Ty, 0))
                        ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
                    }
                }
            }
        }


        std::cout << "Start guardian instrumentation for function: " << fname << std::endl;
        if((!LoadSummary.empty() || !TargetFile.empty()) && v_guard.find(&F) != v_guard.end()
           && (!v_guard.at(&F).valResult.empty()
               || !v_guard.at(&F).argResult.empty()
               || !v_guard.at(&F).unreachableBBs.empty())) {
            std::cout << "Function " << fname << " has guards" << std::endl;

            ArrayRef<Type *> params = ArrayRef<Type *>(Int32Ty);
            FunctionType *fType = FunctionType::get(Type::getVoidTy(M.getContext()), params, false);

            auto exit = BasicBlock::Create(M.getContext(), "EXIT_INT_" + fname, &F);
            IRBuilder<> builder(exit);

            // add callback for fuzzer
            if (Profile) {
                LoadInst *MapPtr = builder.CreateLoad(AFLMapPtr);
                Value *MapFilterPtr = builder.CreateBitCast(
                        builder.CreateGEP(MapPtr, MapFilterLoc), LargestType->getPointerTo());
                LoadInst *MapFilter = builder.CreateLoad(MapFilterPtr);
                MapFilter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

                Value *IncrFilter = builder.CreateAdd(MapFilter, One);
                builder.CreateStore(IncrFilter, MapFilterPtr)
                ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
            }

            // insert exit
            if(Debug) {
                std::vector<Value *> printArgs;
                Value *formatStr = builder.CreateGlobalStringPtr("current func before exit, infer f: %s\n");
                printArgs.push_back(formatStr);
                printArgs.push_back(builder.CreateGlobalStringPtr(F.getName()));
                builder.CreateCall(func, printArgs);
            }

            builder.CreateCall(exitF, ConstantInt::get(Int32Ty, 0))->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
            builder.CreateUnreachable();

            std::cout << "Function " << fname << " has built " << std::endl;
            auto func_guard = v_guard.at(&F);

            // insert beacons for intermediate variable
            for (auto beacon : func_guard.valResult) {
                std::cout << "insert oracles for instruction: " << std::endl;
                auto inst = const_cast<Instruction *>(beacon.first);
                auto guards = beacon.second;

                if(inst->isTerminator()) {
                    continue;
                }

                std::cout << "validate type" << std::endl;
                if(inst->getType()->isAggregateType() || inst->getType()->isStructTy() || inst->getType()->isPointerTy()) {
                    std::cout << "structure/pointer type ignore" << std::endl;
                    pointer_guard++;
                    continue;
                }

                auto split_point = inst->getNextNode();
                if (isa<PHINode>(inst)) {
                    split_point = &(*(inst->getParent()->getFirstInsertionPt()));
                }
                else {
                }

                std::cout << "split block " << std::endl;
                auto entry = inst->getParent()->splitBasicBlock(split_point);

                auto term = inst->getParent()->getTerminator();
                std::cout << "remove terminator " << std::endl;
                if(term != nullptr) {
                    std::cout << "removing terminator " << std::endl;
                    term->removeFromParent();
                }


                IRBuilder<> builder_val(inst->getParent());

                Value* check = ConstantInt::get(Int1Ty, 0);

                std::cout << "insert oracles " << std::endl;
                for(auto &guardian : guards) {
                    Value* lower_check;
                    Value* upper_check;
                    switch (guardian.first.getBitWidth()) {
                        case 1:
                            lower_check = builder_val.CreateICmpSLE(ConstantInt::get(Int1Ty, *(int64_t *)guardian.first.getRawData()), inst);
                            upper_check = builder_val.CreateICmpSGE(ConstantInt::get(Int1Ty, *(int64_t *)guardian.second.getRawData()), inst);
                            break;
                        case 8:
                            lower_check = builder_val.CreateICmpSLE(ConstantInt::get(Int8Ty, *(int64_t *)guardian.first.getRawData()), inst);
                            upper_check = builder_val.CreateICmpSGE(ConstantInt::get(Int8Ty, *(int64_t *)guardian.second.getRawData()), inst);
                            break;
                        case 16:
                            lower_check = builder_val.CreateICmpSLE(ConstantInt::get(Int16Ty, *(int64_t *)guardian.first.getRawData()), inst);
                            upper_check = builder_val.CreateICmpSGE(ConstantInt::get(Int16Ty, *(int64_t *)guardian.second.getRawData()), inst);
                            break;
                        case 32:
                            lower_check = builder_val.CreateICmpSLE(ConstantInt::get(Int32Ty, *(int64_t *)guardian.first.getRawData()), inst);
                            upper_check = builder_val.CreateICmpSGE(ConstantInt::get(Int32Ty, *(int64_t *)guardian.second.getRawData()), inst);
                            break;
                        case 64:
                            lower_check = builder_val.CreateICmpSLE(ConstantInt::get(Int64Ty, *(int64_t *)guardian.first.getRawData()), inst);
                            upper_check = builder_val.CreateICmpSGE(ConstantInt::get(Int64Ty, *(int64_t *)guardian.second.getRawData()), inst);
                            break;
                        default:
                            guardian.first.dump();
                            auto new_type = IntegerType::getIntNTy(C, guardian.first.getBitWidth());
                            auto trans = builder_val.CreateZExtOrBitCast(inst, Int64Ty);
                            lower_check = builder_val.CreateICmpSLE(ConstantInt::get(new_type, *(int64_t *)guardian.first.getRawData()), inst);
                            upper_check = builder_val.CreateICmpSGE(ConstantInt::get(new_type, *(int64_t *)guardian.second.getRawData()), inst);
                    }

                    std::cout << "create conjunction/disjunction " << std::endl;

                    auto check_guard = builder_val.CreateAnd(lower_check, upper_check);
                    check = builder_val.CreateOr(check, check_guard);
                }

                builder_val.CreateCondBr(check, entry, exit);
            }

            std::cout << "finish instruction checking " << std::endl;

            // debug
            if (Debug) {
                std::cout << "current entry block " << std::endl;
                std::cerr << "current entry block " << std::endl;
                F.getEntryBlock().dump();
            }

            // insert beacons for function argument
            if(!func_guard.argResult.empty()) {
                std::cout << "prepare for argument validation " << std::endl;
                auto init_point = F.getEntryBlock().getFirstInsertionPt();
                std::cout << "set up ir builder" << std::endl;
                IRBuilder<> builder_arg(&*(init_point));

                Value* check_arg = ConstantInt::get(Int1Ty, 0);
                Instruction* last_inst = nullptr;
                std::cout << func_guard.argResult.empty() << std::endl;

                std::cout << "insert oracle" << std::endl;
                for (auto beacon : func_guard.argResult) {
                    std::cout << "insert oracles for argument: " << std::endl;
                    auto arg = const_cast<Value *>(beacon.first);

                    std::cout << "validate type" << std::endl;
                    if(arg->getType()->isAggregateType() || arg->getType()->isPointerTy()) {
                        std::cout << "structure/pointer type ignore" << std::endl;
                        pointer_guard++;
                        continue;
                    }

                    auto guardians = beacon.second;

                    std::cout << "insert oracles " << std::endl;
                    for(auto& guardian : guardians) {

                        Value* lower_check;
                        Value* upper_check;
                        switch (guardian.first.getBitWidth()) {
                            case 1:
                                lower_check = builder_arg.CreateICmpSLE(ConstantInt::get(Int1Ty, *(int64_t *)guardian.first.getRawData()), arg);
                                upper_check = builder_arg.CreateICmpSGE(ConstantInt::get(Int1Ty, *(int64_t *)guardian.second.getRawData()), arg);
                                break;
                            case 8:
                                lower_check = builder_arg.CreateICmpSLE(ConstantInt::get(Int8Ty, *(int64_t *)guardian.first.getRawData()), arg);
                                upper_check = builder_arg.CreateICmpSGE(ConstantInt::get(Int8Ty, *(int64_t *)guardian.second.getRawData()), arg);
                                break;
                            case 16:
                                lower_check = builder_arg.CreateICmpSLE(ConstantInt::get(Int16Ty, *(int64_t *)guardian.first.getRawData()), arg);
                                upper_check = builder_arg.CreateICmpSGE(ConstantInt::get(Int16Ty, *(int64_t *)guardian.second.getRawData()), arg);
                                break;
                            case 32:
                                lower_check = builder_arg.CreateICmpSLE(ConstantInt::get(Int32Ty, *(int64_t *)guardian.first.getRawData()), arg);
                                upper_check = builder_arg.CreateICmpSGE(ConstantInt::get(Int32Ty, *(int64_t *)guardian.second.getRawData()), arg);
                                break;
                            case 64:
                                lower_check = builder_arg.CreateICmpSLE(ConstantInt::get(Int64Ty, *(int64_t *)guardian.first.getRawData()), arg);
                                upper_check = builder_arg.CreateICmpSGE(ConstantInt::get(Int64Ty, *(int64_t *)guardian.second.getRawData()), arg);
                                break;
                            default:
                                if(Debug) {
                                    guardian.first.dump();
                                }
                                auto trans = builder_arg.CreateZExtOrBitCast(arg, Int64Ty);
                                lower_check = builder_arg.CreateICmpSLE(ConstantInt::get(Int64Ty, *(int64_t *)guardian.first.getRawData()), arg);
                                upper_check = builder_arg.CreateICmpSGE(ConstantInt::get(Int64Ty, *(int64_t *)guardian.second.getRawData()), arg);
                        }

                        std::cout << "create conjunction/disjunction " << std::endl;

                        auto check_guard = builder_arg.CreateAnd(lower_check, upper_check);
                        check_arg = builder_arg.CreateOr(check_arg, check_guard);
                        last_inst = static_cast<Instruction *>(check_arg);

                    }
                }

                auto entry_block = &F.getEntryBlock();
                auto init_inst = last_inst->getNextNode();

                std::cout << "split block " << std::endl;
                auto entry = entry_block->splitBasicBlock(init_inst);

                auto term = last_inst->getParent()->getTerminator();
                std::cout << "remove terminator " << std::endl;
                if(term != nullptr) {
                    std::cout << "removing terminator " << std::endl;
                    term->removeFromParent();
                }

                // termination check
                builder_arg.SetInsertPoint(entry_block);
                builder_arg.CreateCondBr(check_arg, entry, exit);
            }

        }
    }

    // let's preserve something
    if(!LogFile.empty()) {
        std::ofstream log(LogFile, std::ofstream::out | std::ofstream::app);
        log << "num_function: " << num_function << std::endl;
        log << "num_blocks: " << num_block << " skip_block: " << skip_block
            << " skip overall: " << skip_block + null_block << std::endl;
        log << "num_inst: " << num_inst << std::endl;
        log.close();
    }

    /* Say something nice. */

    if (!be_quiet) {

        std::cout << "num_function: " << num_function << std::endl;
        std::cout << "num_blocks: " << num_block << " skip_block: " << skip_block
            << " skip overall: " << skip_block + null_block << std::endl;
        std::cout << "num_inst: " << num_inst << std::endl;

        if (!inst_blocks) WARNF("No instrumentation targets found.");
        else OKF("Instrumented %u locations (%s mode, ratio %u%%).",
                 inst_blocks, getenv("AFL_HARDEN") ? "hardened" :
                              ((getenv("AFL_USE_ASAN") || getenv("AFL_USE_MSAN")) ?
                               "ASAN/MSAN" : "non-hardened"), inst_ratio);

        std::cout << pointer_guard << " of pointer/structure instruction ignore." << std::endl;
    }

    return true;

}

void AFLCoverage::getAnalysisUsage(AnalysisUsage &AU) {
//    AU.addRequired<PrecondInfer>();

}


static void registerAFLPass(const PassManagerBuilder &,
                            legacy::PassManagerBase &PM) {

    PM.add(new AFLCoverage());

}


static RegisterStandardPasses RegisterAFLPass(
        PassManagerBuilder::EP_ModuleOptimizerEarly, registerAFLPass);

static RegisterStandardPasses RegisterAFLPass0(
        PassManagerBuilder::EP_EnabledOnOptLevel0, registerAFLPass);



int main (int argc, char **argv) {
    LLVMContext ctx;
    SMDiagnostic Err;

    cl::ParseCommandLineOptions(argc, argv, "Range analysis...\n");

    std::unique_ptr<Module> M = parseIRFile(InputFilename, Err, ctx);


    if (!M) {
        Err.print(argv[0], errs());
        return -1;
    }

    PassRegistry &Registry = *PassRegistry::getPassRegistry();
    initializeCore(Registry);
    initializeScalarOpts(Registry);
    initializeAnalysis(Registry);
    initializeTransformUtils(Registry);
    initializeInstCombine(Registry);
    initializeTarget(Registry);

    llvm::legacy::PassManager Passes;

    //Passes.add(new PrecondInfer());
    if (Asan) {
        Passes.add(createAddressSanitizerFunctionPass());
    }
    else {
        Passes.add(new AFLCoverage());
    }

    Passes.run(*M.get());


    std::cout << "verify module" << std::endl;
    std::string debug;
    raw_string_ostream ds(debug);
    if(!verifyModule(*M, &ds)){
        std::cout <<"correct module" << std::endl;
    }
    std::cout << ds.str() << std::endl;

    std::cout << "dump the ir file" << std::endl;
    
    std::cout << "dump error info if exists" << std::endl;
    std::cout << ds.str() << std::endl;
    std::error_code EC;
    llvm::raw_fd_ostream oss(OutputFile, EC, sys::fs::F_None);
    M->print(oss, nullptr, false, true);

    return 0;
}
