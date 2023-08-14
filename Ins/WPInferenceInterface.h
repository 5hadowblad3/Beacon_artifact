#ifndef WP_INFERENCE_INTERFACE_H
#define WP_INFERENCE_INTERFACE_H

#include "llvm/IR/Module.h"
#include "llvm/IR/Instruction.h"
#include "llvm/ADT/APInt.h"
#include <vector>
#include <set>
#include <unordered_map>
namespace BackwardAI {
  class WPInferenceInterface {
  public:
    struct FunctionResult {
      std::unordered_map<const llvm::Value*, std::vector<std::pair<llvm::APInt, llvm::APInt>>> argResult;
      std::unordered_map<const llvm::Instruction*, std::vector<std::pair<llvm::APInt, llvm::APInt>>> valResult;
      std::set<const llvm::BasicBlock *> conditionedBBs;
      std::set<const llvm::BasicBlock *> unreachableBBs;

      FunctionResult(decltype(argResult) argRes, decltype(valResult) valRes,
                     decltype(conditionedBBs) condbbs, decltype(unreachableBBs) unreachbbs) :
        argResult(std::move(argRes)), valResult(std::move(valRes)), conditionedBBs(std::move(condbbs)), unreachableBBs(std::move(unreachbbs)) {}

      FunctionResult() {}
    };

    WPInferenceInterface(llvm::Module *M, std::set<const llvm::Instruction*> targets, bool isInterProc);
    ~WPInferenceInterface();
    void run(bool useSolver);
    void dumpResult();


    /// The analysis result is grouped by functions.
    /// Res[f] = funres:FunctionResult
    /// funres.argResult: arg -> range
    ///   -- arg must be inside function f.
    /// funres.valResult: loc -> rng
    ///   -- loc must be inside function f.
    std::unordered_map<const llvm::Function*, FunctionResult> getResult();

  private:
    llvm::Module *M;
    std::set<const llvm::Instruction*> targets;
    bool isInterAnalysis;
    std::unordered_map<const llvm::Function*, FunctionResult> analysisResultByFun;

    void runForTarget(const llvm::Instruction *, bool useSolver);
    unsigned getAsmLineAtInst (const llvm::Instruction *inst) const;
    void dumpTime();
    void dumpMem();

  };

  /// use WPInferenceInterface to perform analysis and persist result.
  /// use PersistenceAnalysisData to deserialize result.
  /// CANNOT be used at the same time.
  class PersistenceAnalysisData {
  public:
    static std::unordered_map<const llvm::Function*, WPInferenceInterface::FunctionResult>
      deserialize(const llvm::Module *, const std::string &resultJson);
  };

  class InstructionDbgInfo {
  public:
      InstructionDbgInfo() {}
      static unsigned instToLine(const llvm::Instruction *);
      static bool hasLineInfo(const llvm::Instruction *);
      static const llvm::Instruction *lineToInst(unsigned);
      static void registerModule(const llvm::Module *M);
  private:
      std::map<unsigned, const llvm::Instruction *> asmLineToInst;
      std::map<const llvm::Instruction *, unsigned> instToAsmLine;
      void buildLineInfoTable(const llvm::Module *M);
      void sanityCheck(const llvm::Module *M);
      static InstructionDbgInfo *instance;


  };

  // extendable date structure for guardian info in each location
  static std::map<std::string, std::map<std::string, bool> > reachable_blocks;

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
      if(instance->instToAsmLine.find(inst) != instance->instToAsmLine.end()) {
          return instance->instToAsmLine.at(inst);
      }
      return 0;

  }

  const llvm::Instruction *InstructionDbgInfo::lineToInst(unsigned line) {
      if(instance->asmLineToInst.find(line) != instance->asmLineToInst.end()) {
          return instance->asmLineToInst.at(line);
      }
      return nullptr;
  }

  bool InstructionDbgInfo::hasLineInfo(const llvm::Instruction *inst) {
      return instance->instToAsmLine.count(inst);

  }
}

// extendable date structure for guardian info in each location
static std::map<std::string, std::map<std::string, bool> > reachable_blocks;

#endif