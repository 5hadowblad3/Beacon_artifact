#ifndef ALIAS_ICFG_H
#define ALIAS_ICFG_H
#include "llvm/IR/Module.h"
#include "llvm/IR/Instruction.h"
#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include <unordered_map>
#include <memory>
#include <unordered_set>
#include <set>

#include "WPA/Andersen.h"

namespace BackwardAI {
  class ICFGNode {
  public:
    enum ICFGNodeKind {
      CALL_NODE,
      RET_NODE,
      ENTRY_NODE,
      EXIT_NODE,
      NORMAL_NODE
    };

    ICFGNode(const llvm::Instruction *inst, ICFGNodeKind k);
    static bool classof(const ICFGNode *) {
      return true;
    }

    static unsigned ICFGNodeID;

    const llvm::Instruction *getInst() const {
      return inst;
    }

    virtual const llvm::Function *getFunc() const {
      if (inst)
        return inst->getFunction();
      else
        return nullptr;
    }

    ICFGNodeKind getKind() const {
      return nodeK;
    }

    unsigned getID() const {
      return nodeID;
    }

    void addNext(std::shared_ptr<ICFGNode> nextN) {
      nextNodes.insert(nextN);
    }

    std::set<std::shared_ptr<ICFGNode>>::const_iterator next_begin() const {
      return nextNodes.begin();
    }

    std::set<std::shared_ptr<ICFGNode>>::const_iterator next_end() const {
      return nextNodes.end();
    }

    std::set<std::shared_ptr<ICFGNode>> getNextNodes() const {
      return nextNodes;
    }

    std::shared_ptr<ICFGNode> findNextNodeInBB(const llvm::BasicBlock *bb) const {
      for (auto node : nextNodes) {
        if (node->getInst() && node->getInst()->getParent() == bb) {
          return node;
        }
      }
      return nullptr;
    }

    std::shared_ptr<ICFGNode> getSingleNextNode() const {
      assert(nextNodes.size() == 1);
      return *(nextNodes.begin());
    }

  private:
    const llvm::Instruction *inst;
    ICFGNodeKind nodeK;
    unsigned nodeID;

    std::set<std::shared_ptr<ICFGNode>> nextNodes;
  };

  template <ICFGNode::ICFGNodeKind K>
  class GenericICFGNode : public ICFGNode {
  public:
    GenericICFGNode(const llvm::Instruction *inst) : ICFGNode(inst, K) {}
    static bool classof(const ICFGNode *N) {
      return N->getKind() == K;
    }
  };


  using ICFGNodeCall = GenericICFGNode<ICFGNode::CALL_NODE>;
  using ICFGNodeRet = GenericICFGNode<ICFGNode::RET_NODE>;
  using ICFGNodeNormal = GenericICFGNode<ICFGNode::NORMAL_NODE>;

  class ICFGNodeEntry : public GenericICFGNode<ICFGNode::ENTRY_NODE> {
  public:
    ICFGNodeEntry (const llvm::Function *fun) : GenericICFGNode<ICFGNode::ENTRY_NODE>(nullptr), fun(fun) {}
    const llvm::Function *getFunc() const override { return fun; }
  private:
    const llvm::Function *fun;
  };

  class ICFGNodeExit : public GenericICFGNode<ICFGNode::EXIT_NODE> {
  public:
    ICFGNodeExit (const llvm::Function *fun) : GenericICFGNode<ICFGNode::EXIT_NODE>(nullptr), fun(fun) {}
    const llvm::Function *getFunc() const override { return fun; }

  private:
    const llvm::Function *fun;
  };

  class AliasAnalysisInterface {
  public:
    llvm::AliasResult alias(llvm::Value* V1, llvm::Value *V2, llvm::Function *fun);
    static AliasAnalysisInterface& get();
  private:
    AliasAnalysisInterface();
    llvm::PassBuilder PB;
    llvm::AAManager AA;
    llvm::FunctionAnalysisManager FAM;
    llvm::FunctionPassManager FPM;

    std::unordered_map<llvm::Function*, llvm::AAResults *> aliasRes;
  };

  class PointerAnalysisInterface {
  public:
    llvm::AliasResult alias(const llvm::Value *v1, const llvm::Value *v2) const;
    std::set<const llvm::Value*> getPts(const llvm::Value *v) const;
    std::set<const llvm::Function*> getIndCallees(llvm::Instruction* inst) const;

    PointerAnalysisInterface(llvm::Module *);
    ~PointerAnalysisInterface();
  private:
    SVFModule *SVFMod = nullptr;
    PointerAnalysis *pta = nullptr;

    std::set<const llvm::Function*> getCalleesByTypeMatching(llvm::Instruction *inst) const;
    const llvm::Function *getFuncForValueInAA(const llvm::Value* val) const {
      const llvm::Function *fun = nullptr; // gross, llvm based alias analysis needs a function context to perform

      if (llvm::isa<llvm::Instruction>(val)) {
        fun = llvm::cast<llvm::Instruction>(val)->getFunction();
      } else if (llvm::isa<llvm::Argument> (val)) {
        fun = llvm::cast<llvm::Argument> (val)->getParent();
      } else {
        assert(llvm::isa<llvm::Constant>(val) && "What else could it be?"); /// constant & global pointers
        fun = nullptr;
      }

      return fun;
    }
  };

  class CGAnalysis {
  public:
    CGAnalysis(llvm::Module *m, const PointerAnalysisInterface *pa);
    std::set<const llvm::Instruction *> getCallsitesForFun(const llvm::Function *callee) const {
      return calleeToCallsites.at(callee);
    }

    bool hasCallsitesForFun(const llvm::Function *callee) const {
      return calleeToCallsites.count(callee);
    }

    llvm::SmallPtrSet<const llvm::Function*, 16> getCalleesForCallsite(const llvm::Instruction * cs) const {
      return callsiteToCallees.at(cs);
    }

    bool hasCalleesForCallsite(const llvm::Instruction * cs) const {
      return callsiteToCallees.count(cs);
    }

    llvm::SmallPtrSet<const llvm::Instruction *, 8> getReturnPointsForFun(const llvm::Function *fun) const {
      return funToRetInsts.at(fun);
    }

    bool hasReturnPointsForFun(const llvm::Function *fun) const {
      return funToRetInsts.count(fun);
    }


  private:
    const PointerAnalysisInterface *pa = nullptr;
    std::unordered_map<const llvm::Function *, std::set<const llvm::Instruction *>> calleeToCallsites;
    std::unordered_map<const llvm::Instruction *, llvm::SmallPtrSet<const llvm::Function*, 16>> callsiteToCallees;
    std::unordered_map<const llvm::Function *, llvm::SmallPtrSet<const llvm::Instruction *, 8>> funToRetInsts;

    void build(llvm::Module *);
  };


  class ICFG {
  public:
    ICFG(llvm::Module *m, bool isReversed);
    std::shared_ptr<ICFGNode> getNode(const llvm::Instruction *inst) const;
    std::shared_ptr<ICFGNode> getCallNode(const llvm::Instruction *) const;
    std::shared_ptr<ICFGNode> getRetNode(const llvm::Instruction *) const;
    std::shared_ptr<ICFGNode> getNormalNode(const llvm::Instruction *) const;
    std::shared_ptr<ICFGNode> getEntryNode(const llvm::Function *) const;
    std::shared_ptr<ICFGNode> getExitNode(const llvm::Function *) const;

    std::unordered_set<const llvm::BasicBlock*> getReachable(const llvm::Instruction *) const;

    static bool isCallInst(const llvm::Instruction *inst) {
      return inst->getOpcode() == llvm::Instruction::Call ||
             inst->getOpcode() == llvm::Instruction::Invoke;
    }

    bool isTrackedCallInst(const llvm::Instruction *inst) const;
    std::set<const llvm::Instruction *> getNextInstNodes(std::shared_ptr<ICFGNode>) const;

    static bool isEntryInst(const llvm::Instruction *inst) {
      return inst == &*(inst->getFunction()->getEntryBlock().begin());
    }

    static bool isExitInst(const llvm::Instruction *inst) {
      return inst->getOpcode() == llvm::Instruction::Ret;
    }

    static bool isEdgeLegal(const std::shared_ptr<ICFGNode> &src, const std::shared_ptr<ICFGNode> &dst);

    const llvm::Instruction *getEntryInst(const llvm::Function *f) const {
      return &*(f->getEntryBlock().begin());
    }

    const CGAnalysis &getCG() const {
      return CG;
    }

    const PointerAnalysisInterface &getPTA() const {
      return pa;
    }

    bool isLoopExitBB(const llvm::BasicBlock *bb) const;
    bool isLoopBB(const llvm::BasicBlock *bb) const;
  private:
    llvm::Module *m;
    bool isReversed;
    PointerAnalysisInterface pa;
    CGAnalysis CG;

    std::unordered_map<unsigned, std::shared_ptr<ICFGNode>> idToNodeM;
    std::unordered_map<const llvm::Instruction*, unsigned> normalInstToId;
    std::unordered_map<const llvm::Instruction*, std::pair<unsigned, unsigned>> callInstToId;
    std::unordered_map<const llvm::Function*, unsigned> funToEntryId;
    std::unordered_map<const llvm::Function*, unsigned> funToExitId;

    std::unordered_set<const llvm::BasicBlock *> loopExitBBs;
    std::unordered_set<const llvm::BasicBlock *> loopBBs;

    mutable std::unordered_set<const ICFGNode*> reachableNodes;

    void build();
    void buildLoopInfo();

    std::pair<std::shared_ptr<ICFGNode>, std::shared_ptr<ICFGNode>> getOrCreateCallNodes(const llvm::Instruction*);
    std::shared_ptr<ICFGNode> getOrCreateNormalNode(const llvm::Instruction*);
    std::shared_ptr<ICFGNode> getOrCreateEntryNode(const llvm::Function*);
    std::shared_ptr<ICFGNode> getOrCreateExitNode(const llvm::Function*);


    std::set<std::shared_ptr<ICFGNode>> addNode(const llvm::Instruction*);
    template<typename NodeT> std::shared_ptr<NodeT> createNode(const llvm::Instruction*);

    std::set<const llvm::Instruction *> getNextInsts(const llvm::Instruction *inst) const;
    std::set<std::shared_ptr<ICFGNode>> getNextNodesIntra(std::shared_ptr<ICFGNode> node) const;
    std::set<std::shared_ptr<ICFGNode>> getNextNodesInter(std::shared_ptr<ICFGNode> node) const;
    std::set<std::shared_ptr<ICFGNode>> getNextNodes(std::shared_ptr<ICFGNode> node) const;
    bool isInterNode(std::shared_ptr<ICFGNode> node) const;

    /// Traversal
    void dfs(const ICFGNode *curNode, std::unordered_set<const ICFGNode *> &visited) const;

    std::vector<std::pair<const ICFGNode *,  /// end of prev segment
          std::pair<const ICFGNode*, std::stack<const ICFGNode *>>>>
    dfsWithCFL(const ICFGNode *curNode, const std::stack<const ICFGNode *> &callStack) const;

    void exhaust(const ICFGNode *curNode,
                 const std::stack<const ICFGNode *> &callStack) const;
    bool loopDetected(std::stack<const ICFGNode *> frame, const llvm::Function *enteredFunc) const;

    bool loopDetected(std::stack<const ICFGNode *> frame, const ICFGNode *node) const;

    void doDfsCFL(const ICFGNode *curNode) const;


  };
}
#endif