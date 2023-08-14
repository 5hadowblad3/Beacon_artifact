#include "llvm/IR/AssemblyAnnotationWriter.h"
#include "llvm/Support/FormattedStream.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Bitcode/BitcodeWriter.h"

#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/prettywriter.h"
#include <fstream>
#include <numeric>
#include <functional>
#include <iterator>
#include <sstream>

#include "deserialize.h"

using namespace llvm;

namespace {
    class InstructionDbgInfo {
    public:
        static unsigned instToLine(const llvm::Instruction *);
        static bool hasLineInfo(const llvm::Instruction *);
        static const llvm::Instruction *lineToInst(unsigned);
        static void registerModule(const llvm::Module *M);
    private:
        InstructionDbgInfo() {}
        std::map<unsigned, const llvm::Instruction *> asmLineToInst;
        std::map<const llvm::Instruction *, unsigned> instToAsmLine;
        void buildLineInfoTable(const llvm::Module *M);
        void sanityCheck(const llvm::Module *M);
        static InstructionDbgInfo *instance;
    };
}

namespace {
    std::string llvmValToStr(const Value *V) {
        std::string str;
        llvm::raw_string_ostream os(str);
        os << *V;

        return os.str();

        /*if (V->getName().str() != "") {
          return V->getName().str();
        } else {
          const void * address = static_cast<const void*>(V);
          std::stringstream ss;
          ss << address;
          std::string addr = ss.str();
          return "tmp_" + addr;
        }*/

    }

    std::string llvmFunToStr(const Function *fun) {
        const void * address = static_cast<const void*>(fun);
        std::stringstream ss;
        ss << address;
        std::string addr = ss.str();

        std::string funName = fun->getName().str() + "_" + addr;
        return funName;
    }

    std::string disjointRangeSetToStr(const std::vector<std::pair<llvm::APInt, llvm::APInt>> &s) {
        auto rngToStr = [] (std::pair<llvm::APInt, llvm::APInt> rng) -> std::string {
            //      auto lb = rng.first.getZExtValue();
            //      auto ub = rng.second.getZExtValue();

            auto slb = rng.first.getSExtValue();
            auto sub = rng.second.getSExtValue();

            std::stringstream ss;
            //      ss << "[" << lb << "(" << slb << ")"<< "," << ub << "(" << sub << ")"<< "]";
            ss << "[" << slb << "," << sub << "]";
            return ss.str();
        };

        std::vector<std::string> rangeStrs;
        std::transform(s.begin(), s.end(), std::back_inserter(rangeStrs), rngToStr);

        auto res = std::accumulate(std::next(rangeStrs.begin()), rangeStrs.end(),
                                   rangeStrs[0], [](std::string s1, std::string s2) {
            return s1 + "∪" + s2;
        });

        return res;
    }

    static std::vector<std::pair<llvm::APInt, llvm::APInt>> strToRange(std::string s, unsigned w) {
        /// [1,2]∪[4,5] ..
        std::vector<std::pair<llvm::APInt, llvm::APInt>> res;

        auto addIntervalToRes = [&res, w] (std::string itvS) {
            std::istringstream iss(itvS);
            char leftBracket, comma, rightBracket;
            int64_t lb, ub;

            auto &stream = iss >> leftBracket >> lb >> comma >> ub >> rightBracket;
            assert(stream.good());

            APInt aplb(w, lb);
            APInt apub(w, ub);
            res.push_back({aplb, apub});
        };

        size_t pos = 0;
        std::string itvS;
        std::string delimiter = "∪";

        while ((pos = s.find(delimiter)) != std::string::npos) {
            itvS = s.substr(0, pos);
            addIntervalToRes(itvS);
            s.erase(0, pos + delimiter.length());
        }

        assert(!s.empty());
        addIntervalToRes(s);

        return res;
    }

}


InstructionDbgInfo *InstructionDbgInfo::instance = nullptr;

void InstructionDbgInfo::registerModule(const llvm::Module *M) {
    static InstructionDbgInfo dbgInfo;
    static bool hasRegistered = false;

    if (hasRegistered) {
        return;
    }

    hasRegistered = true;

    dbgInfo.buildLineInfoTable(M);
    dbgInfo.sanityCheck(M);

    instance = &dbgInfo;
}

void InstructionDbgInfo::buildLineInfoTable(const llvm::Module *M) {
    class InstructionToLineAnnotator : public llvm::AssemblyAnnotationWriter {
    public:
        void emitInstructionAnnot(const Instruction *i,
                                  llvm::formatted_raw_ostream &os) {
            os << "%%%";
            os << (uintptr_t) i;
        }
    };

    InstructionToLineAnnotator a;
    std::string str;
    llvm::raw_string_ostream os(str);
    M->print(os, &a, false, true);
    os.flush();
    const char *s;

    unsigned line = 1;
    for (s=str.c_str(); *s; s++) {
        if (*s=='\n') {
            line++;
            if (s[1]=='%' && s[2]=='%' && s[3]=='%') {
                s += 4;
                char *end;
                unsigned long long value = strtoull(s, &end, 10);
                if (end!=s) {
                    asmLineToInst.insert(std::make_pair(line, (const Instruction*) value));
                    instToAsmLine.insert(std::make_pair((const Instruction*) value, line));
                }
                s = end;
            }
        }
    }
}

void InstructionDbgInfo::sanityCheck(const llvm::Module *M) {
    for (const auto &fun : *M) {
        for (auto iter = inst_begin(fun), eIter = inst_end(fun); iter != eIter; ++iter) {
            const Instruction *inst = &*iter;
            assert(instToAsmLine.count(inst));
        }
    }
}

unsigned InstructionDbgInfo::instToLine(const llvm::Instruction *inst) {
    return instance->instToAsmLine.at(inst);
}

const llvm::Instruction *InstructionDbgInfo::lineToInst(unsigned line) {
    return instance->asmLineToInst.at(line);
}

bool InstructionDbgInfo::hasLineInfo(const llvm::Instruction *inst) {
    return instance->instToAsmLine.count(inst);

}

std::set<const llvm::BasicBlock*> PersistenceAnalysisData::getReachableBBs(const llvm::Module *M, const std::string &fname) {
    InstructionDbgInfo::registerModule(M);

    std::ifstream ifs(fname);
    if (!ifs.is_open()) {
        llvm::errs() << "Unable to open file " << fname << "\n";
        exit(1);
    }


    unsigned line;
    std::vector<unsigned> lines;
    while (ifs >> line)
        lines.push_back(line);

    ifs.close();

    std::set<const llvm::BasicBlock*> res;
    for (auto l : lines) {
        const Instruction * firstInstOfBB = InstructionDbgInfo::lineToInst(l);
        res.insert(firstInstOfBB->getParent());
    }

    return res;
}

std::unordered_map<const llvm::Function*, FunctionResult>
PersistenceAnalysisData::deserialize(const llvm::Module *M, const std::string &resultJson) {
    std::unordered_map<const llvm::Function*, FunctionResult> res;

    InstructionDbgInfo::registerModule(M);
    std::ifstream ifs(resultJson);
    std::string content((std::istreambuf_iterator<char>(ifs)),
                        (std::istreambuf_iterator<char>()));

    rapidjson::Document dom;
    dom.Parse(content.c_str());
    for (auto& funRecord : dom.GetArray()) {
        assert(funRecord.HasMember("funLoc"));
        unsigned funLoc = funRecord["funLoc"].GetUint();
        const Instruction * firstInstOfFunc = InstructionDbgInfo::lineToInst(funLoc);
        const Function *funKey = firstInstOfFunc->getFunction();
        std::unordered_map<const llvm::Value*, std::vector<std::pair<llvm::APInt, llvm::APInt>>> argResult;
        std::unordered_map<const llvm::Instruction*, std::vector<std::pair<llvm::APInt, llvm::APInt>>> valResult;
        std::set<const llvm::BasicBlock *> unreachableBBs;

        assert(funRecord.HasMember("instRes"));
        for (auto &instRes : funRecord["instRes"].GetArray()) {
            unsigned instLoc = instRes["line"].GetUint();
            std::string rangeStr = instRes["range"].GetString();

            const Instruction *llvmInst = InstructionDbgInfo::lineToInst(instLoc);
            unsigned width = llvmInst->getType()->getIntegerBitWidth();
            auto ranges = strToRange(rangeStr, width);

            valResult.insert({llvmInst, ranges});
        }

        assert(funRecord.HasMember("argRes"));
        for (auto &argRes : funRecord["argRes"].GetArray()) {
            unsigned argNo = argRes["argNO"].GetUint();
            std::string rangeStr = argRes["range"].GetString();

            unsigned idx = 0;
            const Argument *arg = nullptr;
            for (auto argIter = funKey->arg_begin(), eIter = funKey->arg_end(); argIter != eIter; ++argIter) {
                if (idx == argNo) {
                    arg = &*argIter;
                    break;
                }
                ++idx;
            }

            assert(arg);
            auto ranges = strToRange(rangeStr, arg->getType()->getIntegerBitWidth());
            argResult.insert({arg, ranges}).second;
        }

        assert(funRecord.HasMember("unreachbb"));
        for (auto &unreachbb : funRecord["unreachbb"].GetArray()) {
            unsigned bbLoc = unreachbb.GetUint();
            const Instruction *llvmInst = InstructionDbgInfo::lineToInst(bbLoc);
            unreachableBBs.insert(llvmInst->getParent());
        }

        FunctionResult funResult(argResult, valResult, {}, unreachableBBs);
        if (argResult.empty() && valResult.empty() && unreachableBBs.empty()) {

        } else {
            res.insert({funKey, funResult}).second;
        }
    }

    return res;
}
