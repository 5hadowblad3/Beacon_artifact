#include "AliasICFG.h"
#include "llvm/Analysis/CFG.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/CallSite.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/Analysis/BasicAliasAnalysis.h"
#include "llvm/Analysis/CFLAndersAliasAnalysis.h"
#include "llvm/Analysis/TypeBasedAliasAnalysis.h"
#include "llvm/Analysis/LoopInfo.h"
#include <stack>
#include <functional>

using namespace BackwardAI;
using namespace llvm;

extern cl::opt<bool> ReachBBOnly;
extern cl::opt<bool> DebugSwitch;
cl::opt<bool>
    EnableFunctionTypeMatching("fp-type-match", cl::init(false));

cl::opt<bool>
    UseCheapAliasAnalysis("use-cheap-alias", cl::init(false));

unsigned ICFGNode::ICFGNodeID = 0;
ICFGNode::ICFGNode(const Instruction *inst, ICFGNodeKind k)
  : inst(inst), nodeK(k), nodeID(ICFGNodeID++) {}

void CGAnalysis::build(llvm::Module *m) {
  auto isCalleeSuitable = [] (const Function *fun) {
      return !fun->empty();
  };

  for (Module::iterator i = m->begin(), ie = m->end(); i != ie; ++i) {
    Function *f = &*i;
    for (inst_iterator iter = inst_begin(*f), eiter = inst_end(*f); iter != eiter; ++iter) {
      Instruction *inst = &*iter;
      if (isa<DbgInfoIntrinsic>(inst)) {
        continue;
      }
      /// %30 = call i32 bitcast (i64 (%struct._IO_FILE*)* @readUInt32 to i32 (%struct._IO_FILE*)*)(%struct._IO_FILE* %29)
      if (ICFG::isCallInst(inst)) {
        CallSite cs(inst);
        llvm::Value* calledVal = cs.getCalledValue()->stripPointerCasts();
        if (calledVal && isa<Function> (calledVal)) {
          Function *callee = cast<Function> (calledVal);
          if (isCalleeSuitable(callee)) {
            calleeToCallsites[callee].insert(inst);
            callsiteToCallees[inst].insert(callee);
          }
        } else {
          auto indCallees = pa->getIndCallees(inst);
          for (auto callee : indCallees) {
            if (isCalleeSuitable(callee)) {
              calleeToCallsites[callee].insert(inst);
              callsiteToCallees[inst].insert(callee);
            }
          }
        }
      } else if (inst->getOpcode() == Instruction::Ret) {
        funToRetInsts[f].insert(inst);
      }
    }
  }
}

CGAnalysis::CGAnalysis(Module *m, const PointerAnalysisInterface *pa) : pa(pa) {
  build(m);
}

AliasAnalysisInterface::AliasAnalysisInterface() {
  AA.registerFunctionAnalysis<llvm::BasicAA>();
//  AA.registerFunctionAnalysis<llvm::CFLAndersAA>();
  AA.registerFunctionAnalysis<llvm::TypeBasedAA>();
  FAM.registerPass([&] { return std::move(AA); });
  PB.registerFunctionAnalyses(FAM);
}

llvm::AliasResult AliasAnalysisInterface::alias(Value* V1, Value *V2, Function *fun) {
  if (isa<Instruction> (V1) && isa<Instruction> (V2)) {
    assert(cast<Instruction> (V1)->getFunction() == fun);
    assert(cast<Instruction> (V2)->getFunction() == fun);
  }

  if (aliasRes.count(fun)) {
    return aliasRes[fun]->alias(V1, V2);
  } else {
    llvm::PreservedAnalyses PA = FPM.run(*fun, FAM);
    auto AliasResult = &FAM.getResult<llvm::AAManager>(*fun);
    aliasRes.insert({fun, AliasResult});
    return AliasResult->alias(V1, V2);
  }
}

AliasAnalysisInterface& AliasAnalysisInterface::get() {
  static AliasAnalysisInterface res;
  return res;
}

PointerAnalysisInterface::PointerAnalysisInterface(llvm::Module *M) {
  if (!UseCheapAliasAnalysis) {
    SVFMod = new SVFModule(M);
    pta = new AndersenWaveDiff();
    pta->analyze(*SVFMod);
  }
}

PointerAnalysisInterface::~PointerAnalysisInterface() {
  delete pta;
  delete SVFMod;
}

llvm::AliasResult PointerAnalysisInterface::alias(const llvm::Value *v1, const llvm::Value *v2) const {
  if (UseCheapAliasAnalysis) {
    auto fun1 = getFuncForValueInAA(v1), fun2 = getFuncForValueInAA(v2);

    if (fun1 != fun2) {
      return llvm::MayAlias;
    }

    if (fun1 == nullptr) {
      return llvm::MayAlias;
    }

    return AliasAnalysisInterface::get().alias(const_cast<llvm::Value*>(v1), const_cast<llvm::Value*>(v2),
                                               const_cast<llvm::Function*>(fun1));
  } else {
    return pta->alias(v1, v2);
  }
}

std::set<const llvm::Value*> PointerAnalysisInterface::getPts(const llvm::Value *v) const {
  assert(!UseCheapAliasAnalysis);

  std::set<const llvm::Value*> res;
  PAG* pag = pta->getPAG();
  auto nodeID = pag->getValueNode(v);
  auto nodeBS = pta->getPts(nodeID);

  for (auto n : nodeBS) {
    auto pagN = pag->getPAGNode(n);
    if (pagN->hasValue()) {
      res.insert(pagN->getValue());
    }
  }

  return res;
}

std::set<const llvm::Function*> PointerAnalysisInterface::getIndCallees(llvm::Instruction* inst) const {
  assert(inst->getOpcode() == Instruction::Call || inst->getOpcode() == Instruction::Invoke);

  if (UseCheapAliasAnalysis) {
    return getCalleesByTypeMatching(inst);
  }

  llvm::CallSite cs(inst);

  auto ptCG = pta->getPTACallGraph();
  if (ptCG->hasIndCSCallees(cs)) {
    return ptCG->getIndCSCallees(cs);
  } else {
    return getCalleesByTypeMatching(inst);
  }
}

/// Ugly fix because SVF for llvm 4 fails to resolve many function pointers in c++
static bool isFunctionTypeMatched(const llvm::FunctionType *srcTy, const llvm::FunctionType *dstTy) {
  if (!ReachBBOnly && !EnableFunctionTypeMatching) {
    return srcTy == dstTy;
  }

  /// condition for heuristics: either generating reachbbs or explicitly enabling matching function pointers

  auto stripAllLevalPointer = [] (const llvm::Type *ty) {
    auto resTy = ty;
    while(isa<PointerType>(resTy)) {
      resTy = cast<PointerType>(resTy)->getElementType();
    }
    return resTy;
  };


  if (srcTy == dstTy) {
    return true;
  }

  if (srcTy->getNumParams() != dstTy->getNumParams()) {
    return false;
  }

  unsigned numParams = srcTy->getNumParams();
  for (unsigned i = 0; i < numParams; ++i) {
    auto srcParamTy = srcTy->getParamType(i);
    auto dstParamTy = dstTy->getParamType(i);

    if (srcParamTy == dstParamTy)
      continue;

    // only one of them is a pointer
    if (isa<PointerType>(srcParamTy) ^ isa<PointerType>(dstParamTy)) {
      return false;
    }

    auto srcParamElemTy = stripAllLevalPointer(srcParamTy);
    auto dstParamElemTy = stripAllLevalPointer(dstParamTy);

    if (srcParamElemTy->getTypeID() != dstParamElemTy->getTypeID()) {
      return false;
    }



    // heuristics, llvm may rename struct type, see: https://lowlevelbits.org/type-equality-in-llvm/
    // ex. void (%struct.jpeg_compress_struct.170*)
//    if (isa<StructType>(srcParamElemTy)) {
//      if (srcParamElemTy->getStructNumElements() != dstParamElemTy->getStructNumElements()) {
//        return false;
//      }
//
//      auto srcParamName = srcParamElemTy->getStructName().str();
//      auto dstParamName = dstParamElemTy->getStructName().str();
//
//      // check starts with relation: %struct.jpeg_compress_struct.170* and %struct.jpeg_compress_struct are the same struct
//      if (srcParamName.rfind(dstParamName, 0) == 0 ||
//          dstParamName.rfind(srcParamName, 0) == 0) {
//        continue;
//      }  else {
//        /// adhoc fix for c++ class hierarchy:
//        /// i1 (%class.StdinPDFDocBuilder*, %class.GooString*)*
//        /// i1 (%class.OutStream*, %class.GooString*)*
//        ///
//        /// %class.StdinPDFDocBuilder = type { %class.OutStream }
//        /// FIXME: Need a general class hierarchy analysis!
//        if (srcParamElemTy->getNumContainedTypes() == 1 && srcParamElemTy->getContainedType(0) == dstParamElemTy) {
//          continue;
//        }
//
//        if (dstParamElemTy->getNumContainedTypes() == 1 && dstParamElemTy->getContainedType(0) == srcParamElemTy) {
//          continue;
//        }
//
//        return false;
//      }
//
//    } else {
//      return false;
//    }

  }

  return true;
}

std::set<const llvm::Function*> PointerAnalysisInterface::getCalleesByTypeMatching(llvm::Instruction *inst) const {
  CallSite cs(inst);
  llvm::Value* calledVal = cs.getCalledValue()->stripPointerCasts();
  assert(calledVal && !isa<Function> (calledVal));

  std::set<const llvm::Function*> matches;
  if (!calledVal->getType()->isPointerTy()) {
    return matches;
  }

  auto calledValTy = calledVal->getType()->getPointerElementType();
  if (!calledValTy->isFunctionTy()) {
    return matches;
  }

  const llvm::Module *M = inst->getFunction()->getParent();
  for (auto iter = M->begin(), eIter = M->end(); iter != eIter; ++iter) {
    const llvm::Function *fun = &*iter;

    if (isFunctionTypeMatched(cast<FunctionType> (fun->getType()->getPointerElementType()),
                              cast<FunctionType> (calledValTy))) {
      matches.insert(fun);
    }

  }

  return matches;
}


ICFG::ICFG(Module *m, bool isReversed) : m(m), isReversed(isReversed), pa(m), CG(m, &pa) {
  build();
}

std::shared_ptr<ICFGNode> ICFG::getNode(const llvm::Instruction *inst) const {
  if (isTrackedCallInst(inst)) {
    return isReversed ? getRetNode(inst) : getCallNode(inst);
  } else {
    return getNormalNode(inst);
  }
}

bool ICFG::isEdgeLegal(const std::shared_ptr<ICFGNode> &src, const std::shared_ptr<ICFGNode> &dst) {
  auto srcKind = src->getKind(), dstKind = dst->getKind();
  static std::set<std::pair<ICFGNode::ICFGNodeKind, ICFGNode::ICFGNodeKind>> legalEdges = {
      std::make_pair(ICFGNode::NORMAL_NODE, ICFGNode::NORMAL_NODE),
      std::make_pair(ICFGNode::NORMAL_NODE, ICFGNode::RET_NODE),
      std::make_pair(ICFGNode::NORMAL_NODE, ICFGNode::ENTRY_NODE),
      std::make_pair(ICFGNode::EXIT_NODE, ICFGNode::NORMAL_NODE),
      std::make_pair(ICFGNode::ENTRY_NODE, ICFGNode::CALL_NODE),
      std::make_pair(ICFGNode::RET_NODE, ICFGNode::EXIT_NODE),
      std::make_pair(ICFGNode::CALL_NODE, ICFGNode::NORMAL_NODE),
      std::make_pair(ICFGNode::CALL_NODE, ICFGNode::RET_NODE),
      std::make_pair(ICFGNode::CALL_NODE, ICFGNode::ENTRY_NODE),
  };

  return legalEdges.count({srcKind, dstKind});
}

std::set<const Instruction *> ICFG::getNextInstNodes(std::shared_ptr<ICFGNode> curN) const {
  std::set<const Instruction *> res;
  auto nextNodes = curN->getNextNodes();
  std::set<std::shared_ptr<ICFGNode>> instNodes;

  for (auto nextN : nextNodes) {
    if (isa<ICFGNodeExit>(nextN.get())) {
      instNodes.insert(nextN->next_begin(), nextN->next_end());
    } else if (isa<ICFGNodeEntry>(nextN.get())) {
      instNodes.insert(nextN->next_begin(), nextN->next_end());
    } else {
      assert(nextN->getInst());
      instNodes.insert(nextN);
    }
  }

  for (auto n : instNodes) {
    assert(n->getInst());
    res.insert(n->getInst());
  }

  return res;
}

void ICFG::build() {

  for (Module::iterator i = m->begin(), ie = m->end(); i != ie; ++i) {
    Function *f = &*i;
    if (f->empty()) {
      continue;
    }

    for (auto iter = inst_begin(*f), eIter = inst_end(*f); iter != eIter; ++iter) {
      Instruction *inst = &*iter;
      if (isTrackedCallInst(inst)) {
        getOrCreateCallNodes(inst);
      } else {
        getOrCreateNormalNode(inst);
      }
    }

    getOrCreateEntryNode(f);
    getOrCreateExitNode(f);
  }

  for (auto iter = idToNodeM.begin(), eIter = idToNodeM.end(); iter != eIter; ++iter) {
    auto node = iter->second;
    for (auto nextN : getNextNodes(node)) {
      node->addNext(std::move(nextN));
    }
  }

  buildLoopInfo();
}

void ICFG::buildLoopInfo() {
  auto getAllSubloops = [] (const Loop *loop) {
    std::vector<Loop *> stack = loop->getSubLoops();
    std::set<Loop *> visited (stack.begin(), stack.end());

    while (!stack.empty()) {
      Loop * curLoop = stack.back();
      stack.pop_back();

      auto subLoops = curLoop->getSubLoops();
      for (auto l : subLoops) {
        if (!visited.count(l)) {
          visited.insert(l);
          stack.push_back(l);
        }
      }

    }

    visited.insert(const_cast<Loop*>(loop));
    return visited;
  };

  for (Function &fun : *m) {
    if (fun.empty()) {
      continue;
    }
    DominatorTree domTree(fun);
    LoopInfo loopInfo(domTree);
    for (Loop *topLevelLoop : loopInfo) {
      auto allLoops = getAllSubloops(topLevelLoop);
      for (auto loop : allLoops) {
        llvm::SmallVector<llvm::BasicBlock *, 4> exits;
        loop->getExitBlocks(exits);

        for (auto exitBB : exits) {
          loopExitBBs.insert(exitBB);
        }
      }

      auto bbVec = topLevelLoop->getBlocks();
      loopBBs.insert(bbVec.begin(), bbVec.end());
    }
  }
}

bool ICFG::isLoopExitBB(const llvm::BasicBlock *bb) const {
  return loopExitBBs.count(bb);
}

bool ICFG::isLoopBB(const llvm::BasicBlock *bb) const {
  return loopBBs.count(bb);
}

bool ICFG::isTrackedCallInst(const llvm::Instruction *inst) const {
  return isCallInst(inst) && CG.hasCalleesForCallsite(inst);
}

bool ICFG::isInterNode(std::shared_ptr<ICFGNode> node) const {
  if (isReversed) {
    if (isa<ICFGNodeEntry> (node.get()) ) {
      const Function *fun = cast<ICFGNodeEntry>(node.get())->getFunc();
      return CG.hasCallsitesForFun(fun);
    }

    if (isa<ICFGNodeRet> (node.get())) {
      assert(isTrackedCallInst(node->getInst()));
      return true;
    }

    return false;
  } else {
    if (isa<ICFGNodeExit>(node.get())) {
      const Function *fun = cast<ICFGNodeExit>(node.get())->getFunc();
      return CG.hasCallsitesForFun(fun);
    }

    if (isa<ICFGNodeCall> (node.get())) {
      assert(isTrackedCallInst(node->getInst()));
      return true;
    }

    return false;
  }
}

std::set<std::shared_ptr<ICFGNode>> ICFG::getNextNodes(std::shared_ptr<ICFGNode> node) const {
  if (isInterNode(node)) {
    return getNextNodesInter(node);
  } else {
    return getNextNodesIntra(node);
  }
}

std::set<std::shared_ptr<ICFGNode>> ICFG::getNextNodesInter(std::shared_ptr<ICFGNode> node) const {
  std::set<std::shared_ptr<ICFGNode>> res;

  if (isReversed) {
    if (isa<ICFGNodeRet> (node.get())) { /// ret --> exit
      auto callees = CG.getCalleesForCallsite(node->getInst());
      for (auto fun : callees) {
        res.insert(getExitNode(fun));
      }
    } else if (isa<ICFGNodeEntry> (node.get())) { /// entry --> call
      const Function *fun = cast<ICFGNodeEntry>(node.get())->getFunc();
      auto CSs = CG.getCallsitesForFun(fun);
      for (auto i : CSs) {
        res.insert(getCallNode(i));
      }
    } else {
      assert(0);
    }
  } else {
    if (isa<ICFGNodeCall> (node.get())) { /// call --> entry
      auto callees = CG.getCalleesForCallsite(node->getInst());
      for (auto fun : callees) {
        res.insert(getEntryNode(fun));
      }
    } else if (isa<ICFGNodeExit>(node.get())) { /// exit --> ret
      const Function *fun = cast<ICFGNodeExit>(node.get())->getFunc();
      auto CSs = CG.getCallsitesForFun(fun);
      for (auto i : CSs) {
        res.insert(getRetNode(i));
      }
    } else {
      assert(0);
    }
  }

  return res;
}

std::set<std::shared_ptr<ICFGNode>> ICFG::getNextNodesIntra(std::shared_ptr<ICFGNode> node) const {
  std::set<std::shared_ptr<ICFGNode>> res;

  if (isa<ICFGNodeEntry> (node.get())) {
    if (isReversed) { // for function that has no tracked callsites
      return res;
    }

    const Function *f = cast<ICFGNodeEntry>(node.get())->getFunc();
    const Instruction *firstI = getEntryInst(f);
    if (isTrackedCallInst(firstI)) {
      res.insert(getCallNode(firstI));
    } else {
      res.insert(getNormalNode(firstI));
    }
    return res;
  } else if (isa<ICFGNodeExit> (node.get())) {
    if (!isReversed) { // for function that has no tracked callsites
      return res;
    }

    const Function *f = cast<ICFGNodeExit>(node.get())->getFunc();
    if (CG.hasReturnPointsForFun(f)) {
      for (auto i : CG.getReturnPointsForFun(f)) {
        res.insert(getNormalNode(i));
      }
    }

    return res;
  }

  const Instruction *inst = node->getInst();
  assert(inst);

  for (auto i : getNextInsts(inst)) {
    if (isTrackedCallInst(i)) {
      auto nextN = isReversed ? getRetNode(i) : getCallNode(i);
      res.insert(nextN);
    } else {
      res.insert(getNormalNode(i));
    }
  }

  const Function *fun = inst->getFunction();
  if (isReversed) {
    if (isEntryInst(inst)) {
      res.insert(getEntryNode(fun));
      assert(res.size() == 1);
    }
  } else {
    if (isExitInst(inst)) {
      res.insert(getExitNode(fun));
      assert(res.size() == 1);
    }
  }

  return res;
}

/// based on intra-cfg
std::set<const Instruction *> ICFG::getNextInsts(const Instruction *inst) const {
  std::set<const Instruction *> res;

  if (isReversed) {
    if (inst->getPrevNode()) {
      res.insert(inst->getPrevNode());
    } else {
      auto bb = inst->getParent();
      for (auto iter = pred_begin(bb); iter != pred_end(bb); ++iter) {
        res.insert((*iter)->getTerminator());
      }
    }
  } else {
    if (inst->getNextNode()) {
      res.insert(inst->getNextNode());
    } else {
      auto bb = inst->getParent();
      for (auto iter = succ_begin(bb); iter != succ_end(bb); ++iter) {
        res.insert(&*(iter->begin()));
      }
    }
  }


  return res;
}

namespace BackwardAI {
  template<> std::shared_ptr<ICFGNodeCall> ICFG::createNode(const Instruction* inst) {
    auto node = std::make_shared<ICFGNodeCall>(inst);
    assert(idToNodeM.insert({node->getID(), node}).second);
    assert(!callInstToId.count(inst));
    callInstToId[inst].first = node->getID();
    return node;
  }

  template<> std::shared_ptr<ICFGNodeRet> ICFG::createNode(const Instruction* inst) {
    auto node = std::make_shared<ICFGNodeRet>(inst);
    assert(idToNodeM.insert({node->getID(), node}).second);
    assert(callInstToId.count(inst));
    callInstToId[inst].second = node->getID();
    return node;
  }
}

std::shared_ptr<ICFGNode> ICFG::getCallNode(const Instruction *inst) const {
  return idToNodeM.at(callInstToId.at(inst).first);
}

std::shared_ptr<ICFGNode> ICFG::getRetNode(const Instruction *inst) const {
  return idToNodeM.at(callInstToId.at(inst).second);
}

std::shared_ptr<ICFGNode> ICFG::getNormalNode(const Instruction *inst) const {
  return idToNodeM.at(normalInstToId.at(inst));
}

std::shared_ptr<ICFGNode> ICFG::getEntryNode(const llvm::Function *fun) const {
  return idToNodeM.at(funToEntryId.at(fun));
}

std::shared_ptr<ICFGNode> ICFG::getExitNode(const llvm::Function *fun) const {
  return idToNodeM.at(funToExitId.at(fun));
}

void ICFG::dfs(const ICFGNode *curNode, std::unordered_set<const ICFGNode *> &visited) const {
  if (visited.count(curNode)) {
    return;
  }

  visited.insert(curNode);

  for (const auto &nextN : curNode->getNextNodes()) {
    dfs(nextN.get(), visited);
  }

}

bool ICFG::loopDetected(std::stack<const ICFGNode *> frame, const llvm::Function *enteredFunc) const {
  while (!frame.empty()) {
    auto node = frame.top();
    frame.pop();

    if (node->getFunc() == enteredFunc) {
      return true;
    }
  }

  return false;
}

bool ICFG::loopDetected(std::stack<const ICFGNode *> frame, const ICFGNode *node) const {
  while (!frame.empty()) {
    auto curNode = frame.top();
    frame.pop();

    if (curNode == node) {
      return true;
    }
  }

  return false;
}


void ICFG::exhaust(const ICFGNode *curNode, const std::stack<const ICFGNode *> &callStack) const {
  auto pushedCallStack = [] (std::stack<const ICFGNode *> cs, const ICFGNode *node) {
      cs.push(node);
      return cs;
  };

  auto poppedCallStack = [] (std::stack<const ICFGNode *> cs) {
      cs.pop();
      return cs;
  };

  static std::unordered_set<const llvm::Function *> ShortCircuit;

  auto entryNode = getEntryNode(curNode->getFunc()).get();

  std::stack<const ICFGNode *> localDfsStack;
  std::unordered_set<const ICFGNode *> localVisited;

  localDfsStack.push(curNode);
  localVisited.insert(curNode);

  while (!localDfsStack.empty()) {
    auto node = localDfsStack.top();
    auto nodeK = node->getKind();
    localDfsStack.pop();
    assert(localVisited.count(node));

    if (nodeK == ICFGNode::RET_NODE) {
      bool hasLoop = loopDetected(callStack, node);
      for (const auto &nextN : node->getNextNodes()) {
        assert(nextN->getKind() == ICFGNode::EXIT_NODE);
        auto fun = nextN->getFunc();
        if (hasLoop || ShortCircuit.count(fun)) {
          if (hasLoop && DebugSwitch)  llvm::errs() << "Detecting backedge(RET)!!\n";
        } else {
          exhaust(nextN.get(), pushedCallStack(callStack, node));
        }
      }

      auto callNode = getCallNode(node->getInst()).get();
      if (localVisited.count(callNode)) {
        continue;
      }

      localVisited.insert(callNode);
      localDfsStack.push(callNode);

    } else if (nodeK == ICFGNode::ENTRY_NODE) {
      if (node == entryNode) {
        continue;
      }

      for (const auto &nextN : node->getNextNodes()) {
        assert(nextN->getKind() == ICFGNode::CALL_NODE);
        std::stack<const ICFGNode *> newCallStack;

        assert(!callStack.empty() && "You should have hit entry first");
        assert(callStack.top()->getKind() == ICFGNode::RET_NODE);
        if (callStack.top()->getInst() == nextN->getInst()) {
          newCallStack = poppedCallStack(callStack);
        } else { /// context not match
          continue;
        }

        /// The general handling (instead of exhausting a function)

//        if (callStack.empty()) {
//          newCallStack = pushedCallStack(callStack, nextN.get());
//        } else {
//          if (callStack.top()->getInst() == nextN->getInst()) {
//            assert(callStack.top()->getKind() == ICFGNode::RET_NODE && "Recursive calls should be handled");
//            newCallStack = poppedCallStack(callStack);
//          } else if (callStack.top()->getKind() == ICFGNode::CALL_NODE) {
//            if (loopDetected(callStack, node->getFunc())) {
//              llvm::errs() << "Detecting backedge(CALL)!!\n";
//              continue;
//            } else {
//              newCallStack = pushedCallStack(callStack, nextN.get());
//            }
//          }  else { /// otherwise nextN not match!
//            continue;
//          }
//        }

        exhaust(nextN.get(), newCallStack);
      }

    } else {
      for (const auto &nextN : node->getNextNodes()) {
        if (localVisited.count(nextN.get())) {
          continue;
        }

        localVisited.insert(nextN.get());
        localDfsStack.push(nextN.get());
      }
    }

  }

  /// if we starts from exit node, then the function is throughly explored
  if (curNode->getKind() == ICFGNode::EXIT_NODE) {
    ShortCircuit.insert(entryNode->getFunc());
  }

  reachableNodes.insert(localVisited.begin(), localVisited.end());

  if (DebugSwitch) {
    llvm::errs() << "Finish exhausting function " << curNode->getFunc()->getName().str() << "\n";
  }

}


void ICFG::doDfsCFL(const ICFGNode *curNode) const {
//  std::stack<const ICFGNode *> callStack;
//  exhaust(curNode, callStack);

  std::stack<std::pair<const ICFGNode *, std::stack<const ICFGNode *>>> wl;
  std::unordered_set<const ICFGNode *> visited;

  wl.push(std::make_pair(curNode, std::stack<const ICFGNode *>()));
  visited.insert(curNode);

  while(!wl.empty()) {
    auto nodeCS = wl.top();
    wl.pop();
    auto node = nodeCS.first;
    auto cs = nodeCS.second;

    assert(visited.count(node));
    auto entryNode = getEntryNode(node->getFunc()).get();
    exhaust(node, std::stack<const ICFGNode *>());

    for (const auto &nextN : entryNode->getNextNodes()) {
      assert(nextN->getKind() == ICFGNode::CALL_NODE);
      if (loopDetected(cs, nextN.get())) {
        if (DebugSwitch) {
          llvm::errs() << "Detecting backedge(CALL)!!\n";
        }
      } else {
        if (!visited.count(nextN.get())) {
          visited.insert(nextN.get());
          auto csbak = cs; csbak.push(nextN.get());
          wl.push(std::make_pair(nextN.get(), std::move(csbak)));
        }
      }
    }
  }
}

std::vector<std::pair<const ICFGNode *,  /// end of prev segment
                      std::pair<const ICFGNode*, std::stack<const ICFGNode *>>>>
ICFG::dfsWithCFL(const ICFGNode *curNode,
                 const std::stack<const ICFGNode *> &callStack) const {
  /// thoroughly explore a segment with CFL considered, return the starting configurations for next segments
  /// Types of segment:
  /// EXIT -> RET
  /// EXIT -> ENTRY
  /// NORMAL -> RET
  /// NORMAL -> ENTRY
  /// CALL -> RET
  /// CALL -> ENTRY
  /// RET
  /// ENTRY

  auto loopDetected = [] (std::stack<const ICFGNode *> frame, const llvm::Function *enteredFunc) {
      while (!frame.empty()) {
        auto node = frame.top();
        frame.pop();

        if (node->getFunc() == enteredFunc) {
          return true;
        }
      }

      return false;
  };

  auto pushedCallStack = [] (std::stack<const ICFGNode *> cs, const ICFGNode *node) {
    cs.push(node);
    return cs;
  };

  auto poppedCallStack = [] (std::stack<const ICFGNode *> cs) {
    cs.pop();
    return cs;
  };



  std::vector<std::pair<const ICFGNode *,  /// end of prev segment
                        std::pair<const ICFGNode*, std::stack<const ICFGNode *>>>> nextElems;

  auto addToNext = [] (std::vector<std::pair<const ICFGNode *, std::pair<const ICFGNode*, std::stack<const ICFGNode *>>>> &next,
                       const ICFGNode *node, const std::stack<const ICFGNode *> &calls,
                       const ICFGNode *prevNode) {
    next.emplace_back(std::make_pair(prevNode, std::make_pair(node, calls)));
  };

  std::stack<const ICFGNode *> localDfsStack;
  std::unordered_set<const ICFGNode *> localVisited;

  localDfsStack.push(curNode);
  localVisited.insert(curNode);

  while (!localDfsStack.empty()) {
    auto node = localDfsStack.top();
    localDfsStack.pop();
    assert(localVisited.count(node));

    auto nodeK = node->getKind();

    /// When hitting targets, do not add things to the localDfsStack
    if (nodeK == ICFGNode::RET_NODE) {
      for (const auto &nextN : node->getNextNodes()) {
        assert(nextN->getKind() == ICFGNode::EXIT_NODE);
        auto fun = nextN->getFunc();

        bool hasLoop = loopDetected(callStack, fun);
        if (hasLoop) {
          if (DebugSwitch) {
            llvm::errs() << "Detecting backedge(RET)!!\n";
          }

          auto callNode = getCallNode(node->getInst()).get();
          addToNext(nextElems, callNode, callStack, node);
        } else {
          addToNext(nextElems, nextN.get(), pushedCallStack(callStack, node), node);
        }
      }

      continue;
    }

    if (nodeK == ICFGNode::ENTRY_NODE) {
      for (const auto &nextN : node->getNextNodes()) {
        assert(nextN->getKind() == ICFGNode::CALL_NODE);
        if (callStack.empty()) {
          addToNext(nextElems, nextN.get(), pushedCallStack(callStack, nextN.get()), node);
        } else {
          if (callStack.top()->getInst() == nextN->getInst()) {
            assert(callStack.top()->getKind() == ICFGNode::RET_NODE && "Recursive calls should be handled");

            addToNext(nextElems, nextN.get(), poppedCallStack(callStack), node);
          } else if (callStack.top()->getKind() == ICFGNode::CALL_NODE) {
            if (loopDetected(callStack, node->getFunc())) {
              if (DebugSwitch) {
                llvm::errs() << "Detecting backedge(CALL)!!\n";
              }
            } else {
              addToNext(nextElems, nextN.get(), pushedCallStack(callStack, nextN.get()), node);
            }
          } /// otherwise nextN not match!
        }
      }

      continue;
    }

    for (const auto &nextN : node->getNextNodes()) {
      if (localVisited.count(nextN.get())) {
        continue;
      }

      localVisited.insert(nextN.get());
      localDfsStack.push(nextN.get());
    }

  }

  return nextElems;
}

std::unordered_set<const llvm::BasicBlock*> ICFG::getReachable(const llvm::Instruction *target) const {
  const ICFGNode *curNode = getNode(target).get();

  reachableNodes.clear();
  doDfsCFL(curNode);

  std::unordered_set<const llvm::BasicBlock*> res;

  for (auto node : reachableNodes) {
    if (node->getInst())
      res.insert(node->getInst()->getParent());
  }

  return res;
}

std::pair<std::shared_ptr<ICFGNode>, std::shared_ptr<ICFGNode>> ICFG::getOrCreateCallNodes(const Instruction* inst) {
  assert(isTrackedCallInst(inst));
  std::set<std::shared_ptr<ICFGNode>> res;
  if (callInstToId.count(inst)) {
    res.insert(idToNodeM.at(callInstToId.at(inst).first));
    res.insert(idToNodeM.at(callInstToId.at(inst).second));
  } else {
    res = addNode(inst);
    assert(res.size() == 2);
  }

  auto iter = res.begin();
  return {*iter, *(++iter)};
}

std::shared_ptr<ICFGNode> ICFG::getOrCreateNormalNode(const Instruction* inst) { // may be call inst with no resolvable callees
  if (normalInstToId.count(inst)) {
    return idToNodeM.at(normalInstToId.at(inst));
  } else {
    auto res = addNode(inst);
    assert(res.size() == 1);
    return *res.begin();
  }
}

std::shared_ptr<ICFGNode> ICFG::getOrCreateEntryNode(const llvm::Function* fun) {
  if (funToEntryId.count(fun)) {
    return idToNodeM.at(funToEntryId.at(fun));
  } else {
    auto node = std::make_shared<ICFGNodeEntry>(fun);
    assert(idToNodeM.insert({node->getID(), node}).second);
    assert(funToEntryId.insert({fun, node->getID()}).second);
    return node;
  }
}

std::shared_ptr<ICFGNode> ICFG::getOrCreateExitNode(const llvm::Function* fun) {
  if (funToExitId.count(fun)) {
    return idToNodeM.at(funToExitId.at(fun));
  } else {
    auto node = std::make_shared<ICFGNodeExit>(fun);
    assert(idToNodeM.insert({node->getID(), node}).second);
    assert(funToExitId.insert({fun, node->getID()}).second);
    return node;
  }
}

std::set<std::shared_ptr<ICFGNode>> ICFG::addNode(const Instruction *inst) {
  std::set<std::shared_ptr<ICFGNode>> nodes;
  if (isTrackedCallInst(inst)) {
    nodes.insert(createNode<ICFGNodeCall>(inst));
    nodes.insert(createNode<ICFGNodeRet>(inst));
  } else {
    nodes.insert(createNode<ICFGNodeNormal>(inst));
  }
  return nodes;
}

template<typename NodeT> std::shared_ptr<NodeT> ICFG::createNode(const Instruction* inst) {
  auto node = std::make_shared<NodeT>(inst);
  assert(idToNodeM.insert({node->getID(), node}).second);
  assert(normalInstToId.insert({inst, node->getID()}).second);
  return node;
}


