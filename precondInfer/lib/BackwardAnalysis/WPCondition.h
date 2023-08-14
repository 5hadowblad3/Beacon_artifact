#ifndef WP_CONDITION_H
#define WP_CONDITION_H
#include "klee/SymbolicAbstractInterface.h"
#include "klee/Expr.h"
#include "klee/Constraints.h"
#include "klee/util/ArrayCache.h"
#include "klee/util/ExprHashMap.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "AbstractState.h"
#include "AliasICFG.h"
#include <unordered_map>
#include <set>
#include <memory>
namespace BackwardAI {
  using SymExpr = klee::ref<klee::Expr>;

  struct ProcessItem {
    std::shared_ptr<ICFGNode> loc;
    SymExpr postCond;
    const llvm::BasicBlock *dst = nullptr;

    ProcessItem(const std::shared_ptr<ICFGNode> &loc, const SymExpr &postCond, const llvm::BasicBlock *dst = nullptr)
      : loc(loc), postCond(postCond), dst(dst) {}

    bool operator<(const ProcessItem &rhs) const {
      if (loc != rhs.loc) {
        return loc < rhs.loc;
      } else if (postCond != rhs.postCond) {
        return postCond.get() < rhs.postCond.get();
      } else {
        return dst < rhs.dst;
      }
    }

    bool operator==(const ProcessItem &rhs) const {
      return loc == rhs.loc && postCond == rhs.postCond && dst == rhs.dst;
    }
  };

  class PreconditionFixpo {
  public:
    PreconditionFixpo(const llvm::Instruction *target,
                      const ICFG &icfg,
                      bool interAnalysis);
    void init();
    void run();

    class FixpointDisjunctiveResult {
    public:
      using APIntBounds = DisjunctiveIntervalSummary::APIntBounds;
    private:
      std::unordered_map<const llvm::Value*, APIntBounds> argResult;
      std::unordered_map<const llvm::Instruction*, APIntBounds> valResult;
      std::set<const llvm::BasicBlock *> conditionedBBs;
      std::set<const llvm::BasicBlock *> unreachableBBs;

    public:
      decltype(valResult) getValResult() const { return valResult; }
      decltype(argResult) getArgResult() const { return argResult; }
      decltype(conditionedBBs) getConditionedBBs() const { return conditionedBBs; }
      decltype(unreachableBBs) getUnreachableBBs() const { return unreachableBBs; }

      void setValResult(const llvm::Instruction* v, APIntBounds bounds) {
        valResult[v] = std::move(bounds);
      }

      void setArgResult(const std::unordered_map<const llvm::Value*, APIntBounds> &argRes) {
        for (const auto &argRange : argRes) {
          argResult.insert(argRange);
        }
      }

      void addArgRange(const llvm::Value* arg, const APIntBounds &bds) {
        argResult.insert({arg, bds});
      }

      void addUnreachableBB(const llvm::BasicBlock *bb) {
        unreachableBBs.insert(bb);
      }

      void addConditionedBB(const llvm::BasicBlock *bb) {
        conditionedBBs.insert(bb);
      }
    };

    std::unordered_map<const llvm::Function*, FixpointDisjunctiveResult> getAnalysisResult();
  private:
    /// initialized at construction time
    const ICFG &icfg;
    const PointerAnalysisInterface &pa;
    mutable absD::RangeComputeInterface rangeComp;
    std::shared_ptr<ICFGNode> targetNode;
    const llvm::DataLayout *DL;
    unsigned PointerSizeInBits;

    std::set<std::shared_ptr<ICFGNode>> reachableNodes;
    std::set<const llvm::Function*> reachableFuncs;

    std::unordered_map<const llvm::Value *, SymExpr> valSym;
    klee::ExprHashMap<const llvm::Value *> symToIntVals;
    std::set<const llvm::Value*> intLLVMVals; //keys of intSym

    mutable klee::ArrayCache arrayCache;
    const std::string INT_SYM = "int"; // for tracked integer
    const std::string TEMP_SYM = "temp"; // for internal temp
    const std::string MEM_SYM = "mem";
    mutable unsigned symid = 0;

    mutable klee::ExprHashMap<std::shared_ptr<AbstractState>> condToAbs;

    /// loaded pointer p --> symbol for *p (no need to track location, as we use a flow-insensitive pointer analysis)
    std::unordered_map<const llvm::Value *, SymExpr> ldPtrToMemSym;
    klee::ExprHashMap<const llvm::Value *> memSymToLdPtr;
    /// (loaded pointer, width of the loaded value), should be 1 to 1 mapping
    std::set<std::pair<const llvm::Value*, unsigned>> memKeys;

    std::set<ProcessItem> processList;

    struct ICFGNodeHash {
      std::size_t operator()(const std::shared_ptr<ICFGNode>& key) const {
        return std::hash<const ICFGNode *> () (key.get());
      }
    };

    struct ICFGNodeEqual {
      bool operator()(const std::shared_ptr<ICFGNode>& t1, const std::shared_ptr<ICFGNode>& t2) const {
        return t1.get() == t2.get();
      }
    };

    std::unordered_map<std::shared_ptr<ICFGNode>, llvm::SmallVector<SymExpr, 8>, ICFGNodeHash, ICFGNodeEqual> stateInMap;
    std::unordered_map<std::shared_ptr<ICFGNode>, llvm::SmallVector<SymExpr, 8>, ICFGNodeHash, ICFGNodeEqual> stateOutMap;

    std::set<std::shared_ptr<ICFGNode>> joinedLocIn;
    std::set<std::shared_ptr<ICFGNode>> joinedLocOut;

    std::shared_ptr<ICFGNode> getNodePre(const llvm::Instruction *inst);
    std::shared_ptr<ICFGNode> getNodePost(const llvm::Instruction *inst);

    void pushProcessList(const ProcessItem &item) {
      processList.insert(item);
    }

    bool isProcessListEmpty() const {
      return processList.empty();
    }

    ProcessItem popProcessList() {
      assert(!isProcessListEmpty());
      auto iter = processList.begin();
      auto item = *iter;
      processList.erase(iter);
      return item;
    }

    void addPostCond(const std::shared_ptr<ICFGNode> &loc, const SymExpr &cond) {
      stateOutMap[loc].push_back(cond);
    }

    void addPreCond(const std::shared_ptr<ICFGNode> &loc, const SymExpr &cond) {
      stateInMap[loc].push_back(cond);
    }

    bool updateState(const std::shared_ptr<ICFGNode> &loc, const SymExpr &cond,
                     bool isPostCond, const llvm::BasicBlock *dst);

    bool updateStateOut(const std::shared_ptr<ICFGNode> &loc, const SymExpr &cond,
                        const llvm::BasicBlock *dst);

    bool updateStateIn(const std::shared_ptr<ICFGNode> &loc, const SymExpr &cond);

    SymExpr getMemSymForPtr(const llvm::Value *ptr) const {
      return ldPtrToMemSym.at(ptr);
    }

    const llvm::Value *getPtrForMemSym (const SymExpr &sym) const {
      return memSymToLdPtr.find(sym)->second;
    }

    void generateMemSym (const llvm::LoadInst *ldInst);

    std::pair<std::set<std::shared_ptr<ICFGNode>>, std::set<const llvm::Function*>> getReachableNodesForTarget() const;

    unsigned getWidthForType(llvm::Type *ty) const;
    SymExpr getTrueCond() const;
    SymExpr getFalseCond() const;
    void addValSym(const llvm::Value *val, const SymExpr &sym);
    void trackSymbolForInst(const llvm::Instruction &inst);
    void trackSymbolForArgs(const llvm::Function *F);
    void trackSymbol();
    /// must be called after all instructions are tracked
    void initSyms();
    bool isValueTracked(const llvm::Value *v) const {
      return valSym.count(v);
    }

    SymExpr getSymForValue(const llvm::Value *v) const { // precondition: isValueTracked(v)
      return valSym.at(v);
    }

    SymExpr generateSymbol(klee::Expr::Width w, const std::string &category, const std::string &suffix = "") const;
    SymExpr invalidatePtrs(const llvm::Value* ptr, SymExpr cond);
    SymExpr invalidateValueInCond(const llvm::Value*, SymExpr cond);
    SymExpr replaceLHSWithUnknownTemp(const llvm::Instruction &I, SymExpr cond);

    std::vector<SymExpr> transferInstData(const llvm::Instruction &I, SymExpr cond);
    SymExpr transferBinaryArithInst(const llvm::Instruction &I, SymExpr cond);
    SymExpr transferBinaryBitwiseInst(const llvm::Instruction &I, SymExpr cond);
    SymExpr transferComparisonInst(const llvm::Instruction &I, SymExpr cond);
    std::vector<SymExpr> transferLoadInst(const llvm::Instruction &I, SymExpr cond);
    std::vector<SymExpr> transferStoreInst(const llvm::Instruction &I, SymExpr cond);
    SymExpr transferGEPInst(const llvm::Instruction &I, SymExpr cond);
    SymExpr transferCallInst(const llvm::Instruction &I, SymExpr cond);
    SymExpr transferSelectInst(const llvm::Instruction &I, SymExpr cond);
    SymExpr transferCastInst(const llvm::Instruction &I, SymExpr cond);

    SymExpr transferCondWithAssign(SymExpr cond, SymExpr lhs, SymExpr rhs) const;
    SymExpr transferCondWithAssigns(SymExpr cond, std::map<SymExpr, SymExpr> eqs) const;

    void transferLocalControl(const std::shared_ptr<ICFGNode> &src, const std::shared_ptr<ICFGNode> &dst, const SymExpr &cond);

    SymExpr transferRetToExit(const llvm::Instruction &callI, const llvm::Instruction &retI, SymExpr cond);
    SymExpr transferEntryToCall(const llvm::Instruction &I, const llvm::Function* fun, SymExpr cond);

    SymExpr transferCallRecvToCallee(const llvm::Instruction &callI, const llvm::Instruction &retI, SymExpr cond);

    std::pair<std::vector<const llvm::Value*>, std::vector<SymExpr>> getConstrainedValSym (SymExpr) const;
    std::vector<SymExpr> getConstrainedMemSym (const SymExpr&) const;
    std::vector<SymExpr> getConstrainedMemValSym (const SymExpr&) const;

    bool isValueConstrained(const llvm::Value *v, SymExpr cond) const;
    std::shared_ptr<AbstractState> symbolicAbstract(SymExpr cond) const;
    SymExpr symbolicConcretize(std::shared_ptr<AbstractState> abs);

    std::shared_ptr<AbstractState> initAbsBot() const;

    void debugFunc(const std::shared_ptr<ICFGNode> &loc, SymExpr cond, const llvm::BasicBlock *dst) const;

  };
}

#endif
