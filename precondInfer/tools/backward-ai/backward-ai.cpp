#include "klee/WPInferenceInterface.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Transforms/Scalar.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/Analysis/CallGraph.h"

#include <set>
#include <fstream>

using namespace llvm;
using namespace BackwardAI;

cl::opt<bool>
    DebugSwitch("enable-debugout", cl::init(false));

cl::opt<bool>
    ReachBBOnly("reachbb-only", cl::init(false));

cl::opt<std::string>
    TargetFile("target-file",
               cl::desc("Specify a file for target instructions, used in backward analysis"));
namespace {
  cl::opt<std::string> InputFilename(cl::Positional, cl::desc("<filename>.bc"), cl::init(""));

  cl::opt<bool>
    DoInterprocAnalysis("inter-backward",
                         cl::init(true));

  cl::opt<std::string>
      BBReachFile("bb-reach-file",
                  cl::desc("Specify a file for bb reaches (used for statistics)"),
                      cl::init(""));

  cl::opt<bool>
    TestDeserialize("deserialize",
                 cl::init(false));

  std::string getDSPIPath (const DILocation &Loc) {
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

  std::set<const Instruction *> getTargetInsts(Module &M, const std::string &scopeFile, std::set<const BasicBlock*> &targetBBs) {
    std::set<const Instruction *> targets;
    std::map <std::pair<std::string, unsigned>, std::set<const Instruction *>> candidates;

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

          auto iter = std::find_if(scopeInfo.begin(), scopeInfo.end(), eqK);
          if (iter != scopeInfo.end()) {
            if (I->getOpcode() != Instruction::PHI) {
              std::pair<std::string, unsigned> key = *iter;
              candidates[key].insert(&*I);
            }
          }
        }
      }
    }

    if (candidates.size() != scopeInfo.size()) {
      llvm::errs() << "malformed target file -- exiting!\n";
      exit(1);
    }

    for (const auto &p : candidates) {
      const std::set<const Instruction *> &instsAtLoc = p.second;
      targets.insert(*instsAtLoc.begin());

      for (auto i : instsAtLoc) {
        targetBBs.insert(i->getParent());
      }
    }

    assert(targets.size() == scopeInfo.size());
    return targets;
  }

  std::set<const llvm::BasicBlock*> parseReachBB(Module &M, const std::string &scopeFile) {
      std::set<const llvm::BasicBlock*> reachableBBs;
      std::ifstream f(scopeFile.c_str(), std::ios::in);
      if (!f.good())
        assert(0 && "unable to open path file");

      std::set<std::pair<std::string, unsigned >> scopeInfo;
      std::string s;
      while (std::getline(f, s)) {
        auto pos = s.find(":");
        assert(pos != std::string::npos);

        std::string fName = s.substr(0, pos);
        std::string line = s.substr(pos+1);

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
             reachableBBs.insert(I->getParent());
           }
         }
       }
     }

     return reachableBBs;
   }

  class PrecondInfer : public ModulePass {
  public:
    static char ID; //!< Pass identification, replacement for typeid
    PrecondInfer() : ModulePass(ID) {}

    virtual bool runOnModule(Module &M);

    virtual void getAnalysisUsage(AnalysisUsage &AU) const {
      AU.setPreservesAll();
    }

  };
}

char PrecondInfer::ID = 0;
static RegisterPass<PrecondInfer> YY("precond-infer",
                                  "precond infer",
                                false, true);

bool PrecondInfer::runOnModule(Module &M) {
  if (TestDeserialize) {
    PersistenceAnalysisData::deserialize(&M, "range_res.txt");
    llvm::errs() << "deserialize done!\n";
  } else {
    std::set<const BasicBlock*> targetBBs;
    auto targets = getTargetInsts(M, TargetFile, targetBBs);
    if (BBReachFile != "") {
      auto reachBBs = parseReachBB(M, BBReachFile);
      llvm::errs() << "Size of reach bb: " << reachBBs.size() << "\n";
    }

    WPInferenceInterface engine(&M, targets, DoInterprocAnalysis);
    engine.dumpReachBBs(targetBBs);

    if (!ReachBBOnly) {
      engine.run(false);
      engine.dumpResult();
    }

  }

  return false;
}

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

  Passes.add(createLowerInvokePass());
  Passes.add(new PrecondInfer());
  Passes.run(*M.get());

  return 0;
}