#include "WPCondition.h"
#include "InstructionDbgInfo.h"
#include "klee/util/ExprVisitor.h"
#include "klee/util/ExprHashMap.h"
#include "klee/util/GetElementPtrTypeIterator.h"
#include "llvm/Analysis/CFG.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/CallSite.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "Util/AnalysisUtil.h"
#include <vector>
#include <deque>
#include <unordered_set>
#include <functional>
#include <numeric>
#include <algorithm>

using namespace BackwardAI;
using namespace klee;
using namespace llvm;

extern cl::opt<bool> DebugSwitch;

namespace {
  cl::opt<unsigned>
    JoinBound("join-bound",
               cl::init(20));
  cl::opt<unsigned>
        WidenBound("widen-bound",
                   cl::init(2));

  cl::opt<unsigned>
    PtsBound("pts-bound",
              cl::init(5));

  cl::opt<std::string>
    DebugFun("debug-func",
             cl::init(""),
             cl::desc("Specify a function name for debugging"));

//  void debugFun(const Function *fun) {
//    static std::unordered_map<const Function *, bool> record;
//    if (record.count(fun))  return;
//    record[fun] = true;
//    for (auto iter = fun->begin(); iter != fun->end(); ++iter) {
//      const BasicBlock *bb = &*iter;
//      const void * address = static_cast<const void*>(bb);
//      llvm::errs() << "bb: " << address << "\n";
//      bb->dump();
//    }
//  }

}

namespace {
  class ExprSafeReplaceVisitor : public ExprVisitor {
  private:
    bool hasError = false;
    void setError() {
      hasError = true;
    }
  public:
    bool errorOccured() const {
      return hasError;
    }

    ExprSafeReplaceVisitor(bool recursive=false) : ExprVisitor(recursive) {}

  protected:
    Action visitDivRemExpr(const BinaryExpr &e) {
      auto K = e.getKind();
      assert(K == Expr::SDiv || K == Expr::UDiv || K == Expr::URem || K == Expr::SRem);

      const auto &divisor = e.right;
      auto divisorTransed = visit(divisor);
      if (errorOccured()) {
        return Action::skipChildren();
      }

      if (divisorTransed->isZero()) {
        setError();
        return Action::skipChildren();
      }

      return Action::doChildren();
    }
  public:
    Action visitSDiv(const SDivExpr &e) {
      return visitDivRemExpr(e);
    }

    Action visitUDiv(const UDivExpr &e) {
      return visitDivRemExpr(e);
    }

    Action visitURem(const URemExpr &e) {
      return visitDivRemExpr(e);
    }

    Action visitSRem(const SRemExpr &e) {
      return visitDivRemExpr(e);
    }
  };

  class ExprReplaceVisitor : public ExprSafeReplaceVisitor {
  private:
    SymExpr src, dst;

  public:
    ExprReplaceVisitor(SymExpr _src, SymExpr _dst) : src(_src), dst(_dst) {}

    Action visitExpr(const Expr &e) {
      if (e == *src.get()) {
        return Action::changeTo(dst);
      } else {
        return Action::doChildren();
      }
    }

    Action visitExprPost(const Expr &e) {
      if (e == *src.get()) {
        return Action::changeTo(dst);
      } else {
        return Action::doChildren();
      }
    }

  };

  class ExprReplaceVisitor2 : public ExprSafeReplaceVisitor {
  private:
    const std::map< SymExpr, SymExpr > &replacements;

  public:
    ExprReplaceVisitor2(const std::map< SymExpr, SymExpr > &_replacements)
      : ExprSafeReplaceVisitor(true),
        replacements(_replacements) {}

    Action visitExprPost(const Expr &e) {
      std::map< SymExpr, SymExpr >::const_iterator it =
        replacements.find(SymExpr(const_cast<Expr*>(&e)));
      if (it!=replacements.end()) {
        return Action::changeTo(it->second);
      } else {
        return Action::doChildren();
      }
    }
  };

  bool isExprSatisfyPredicateAny (SymExpr e, std::function <bool (SymExpr)> p) {
    ExprHashSet visited;
    std::vector<SymExpr> stack;

    stack.push_back(e);
    visited.insert(e);
    while (!stack.empty()) {
      SymExpr curE = stack.back();
      stack.pop_back();

      if (p(curE)) {
        return true;
      }

      for (unsigned i = 0; i != curE->getNumKids(); ++i) {
        SymExpr kidE = curE->getKid(i);
        if (!visited.count(kidE)) {
          stack.push_back(kidE);
          visited.insert(kidE);
        }
      }
    }

    return false;
  }

  std::vector<SymExpr> filterExpr(SymExpr e, std::function <bool (SymExpr)> p) {
    ExprHashSet visited;
    std::vector<SymExpr> stack;
    std::vector<SymExpr> res;

    stack.push_back(e);
    visited.insert(e);
    while (!stack.empty()) {
      SymExpr curE = stack.back();
      stack.pop_back();

      if (p(curE)) {
        res.push_back(curE);
      }

      for (unsigned i = 0; i != curE->getNumKids(); ++i) {
        SymExpr kidE = curE->getKid(i);
        if (!visited.count(kidE)) {
          stack.push_back(kidE);
          visited.insert(kidE);
        }
      }
    }

    return res;
  }

  bool isExprContainSubExpr(SymExpr src, SymExpr dst) {
    std::function <bool (SymExpr)> pred = [dst] (SymExpr exp) {
      return exp == dst;
    };

    return isExprSatisfyPredicateAny(src, pred);
  }

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

  void PrintDebugLocation(Instruction *I) {
    if (MDNode *N = I->getMetadata("dbg")) {
      DILocation *Loc = cast<DILocation>(N);
      std::string File = getDSPIPath(*Loc);
      unsigned Line = Loc->getLine();
      llvm::errs() << File << ":" << Line << "\n";
    }
  }
}

std::shared_ptr<ICFGNode> PreconditionFixpo::getNodePre(const llvm::Instruction *inst) {
  /// we need callnode for tracked call inst
  if (icfg.isTrackedCallInst(inst)) {
    return icfg.getCallNode(inst);
  } else {
    return icfg.getNode(inst);
  }
}

std::shared_ptr<ICFGNode> PreconditionFixpo::getNodePost(const llvm::Instruction *inst) {
  return icfg.getNode(inst);
}

PreconditionFixpo::PreconditionFixpo(const Instruction *target,
                                     const ICFG &icfg, bool interAnalysis)
  : icfg(icfg), pa(icfg.getPTA()) {
  targetNode = getNodePre(target);
  DL = &target->getModule()->getDataLayout();
  PointerSizeInBits = DL->getPointerSizeInBits();
}

unsigned PreconditionFixpo::getWidthForType(llvm::Type *ty) const {
  return DL->getTypeSizeInBits(ty);
}

bool PreconditionFixpo::init() {
  trackSymbol();

  if (valSym.empty()) {
    return false;
  }

  initSyms();

  pushProcessList(ProcessItem(targetNode, getTrueCond()));
  addPostCond(targetNode, getTrueCond());

  return true;
}

SymExpr PreconditionFixpo::getTrueCond() const {
  return klee::ConstantExpr::create(1, 1);
}

SymExpr PreconditionFixpo::getFalseCond() const {
  return klee::ConstantExpr::create(0, 1);
}

std::pair<std::set<std::shared_ptr<ICFGNode>>, std::set<const llvm::Function*>> PreconditionFixpo::getReachableNodesForTarget() const {
  std::set<const Function *> visitedFuncs;

  std::vector<std::shared_ptr<ICFGNode>> stack;
  std::set<std::shared_ptr<ICFGNode>> visitedN;

  visitedN.insert(targetNode);
  stack.push_back(targetNode);

  while (!stack.empty()) {
    auto curN = stack.back();
    stack.pop_back();
    if (curN->getInst()) { // inst undef for entry/exit node
      visitedFuncs.insert(curN->getInst()->getFunction());
    }

    for (auto iter = curN->next_begin(), eIter = curN->next_end(); iter != eIter; ++iter) {
      std::shared_ptr<ICFGNode> nextN = *iter;
      if (!visitedN.count(nextN)) {
        visitedN.insert(nextN);
        stack.push_back(nextN);
      }
    }
  }

  return {visitedN, visitedFuncs};
}

void PreconditionFixpo::addValSym(const Value *val, const SymExpr &sym) {
  valSym.insert({val, sym});
}

void PreconditionFixpo::trackSymbolForInst(const Instruction &inst) {
  if (auto SI = dyn_cast<SwitchInst>(&inst)) {
    for (auto i : SI->cases()) {
      const ConstantInt *caseVal = i.getCaseValue();
      if (caseVal->getType()->getBitWidth() <= 64) {
        addValSym(caseVal, klee::ConstantExpr::alloc(caseVal->getValue()));
      }
    }

    return;
  }

  bool tracked = false;
  if (inst.getType()->isIntegerTy()) {
    auto Ty = dyn_cast<IntegerType>(inst.getType());
    if (Ty->getBitWidth() <= 64) {
      addValSym(&inst, generateSymbol(getWidthForType(Ty), INT_SYM));
      tracked = true;
    }
  }

  if (tracked) {
    for (auto opIter = inst.op_begin(); opIter != inst.op_end(); ++opIter) {
      Value *opnd = *opIter;
      if (isa<ConstantInt>(opnd)) {
        auto cop = cast<ConstantInt> (opnd);
        auto opTy = cop->getType();
        if (getWidthForType(opTy) <= 64) {
          addValSym(cop, klee::ConstantExpr::alloc(cop->getValue()));
        }
      }
    }
  }
}

void PreconditionFixpo::trackSymbol() {
  auto nodesFuns = getReachableNodesForTarget();
  reachableNodes = nodesFuns.first;
  reachableFuncs = nodesFuns.second;

  for (auto node : reachableNodes) {
    if (node->getInst()) {
      trackSymbolForInst(*node->getInst());
    }
  }

  for (auto fun : reachableFuncs) {
    trackSymbolForArgs(fun);
  }

}

void PreconditionFixpo::trackSymbolForArgs(const Function *F) {
  for (auto iter = F->arg_begin(); iter != F->arg_end(); ++iter) {
    const Argument *arg = &*iter;
    if (arg->getType()->isIntegerTy()) {
      auto Ty = dyn_cast<IntegerType>(arg->getType());
      if (Ty->getBitWidth() <= 64) {
        addValSym(arg, generateSymbol(getWidthForType(Ty), INT_SYM));
      }
    }
  }
}

void PreconditionFixpo::initSyms() {
  for (auto iter = valSym.begin(), EIter = valSym.end(); iter != EIter; ++iter) {
    const Value *val = iter->first;
    if (isa<ConstantInt>(val)) {
      continue;
    }
    assert(val->getType()->isIntegerTy());
    SymExpr sym = iter->second;

    assert(intLLVMVals.insert(val).second);
    assert(symToIntVals.insert({sym, val}).second);

    if (auto ldInst = dyn_cast<LoadInst> (val)) {
      generateMemSym(ldInst);
    }
  }
}

SymExpr PreconditionFixpo::generateSymbol(Expr::Width width, const std::string &category, const std::string &suffix) const {
  std::string name = category + "_" + llvm::utostr(++symid);
  if (suffix != "") {
    name += "_" + suffix;
  }

  // There can be case like: %72 = trunc i32 %71 to i12, !dbg !55280
  unsigned sz = (width + 7) / 8; // number of bytes.

  const Array *array = arrayCache.CreateArray(name, sz);
  UpdateList ul(array, 0);
  assert(width <= 64);
  if (width == Expr::Bool) {
      return ZExtExpr::create(ReadExpr::create(ul,
                                               klee::ConstantExpr::alloc(0, Expr::Int32)),
                              Expr::Bool);
  }

  unsigned remainingWidth = width;
  unsigned byteIdx = 0;
  std::vector<SymExpr> components;
  while (remainingWidth >= 8) {
    SymExpr cur = ReadExpr::create(ul,
                                   klee::ConstantExpr::alloc(byteIdx,Expr::Int32));
    ++byteIdx;
    components.push_back(cur);
    remainingWidth -= 8;
  }

  if (remainingWidth != 0) {
    SymExpr cur = ZExtExpr::create(ReadExpr::create(ul,
                                                    klee::ConstantExpr::alloc(byteIdx, Expr::Int32)),
                                   remainingWidth);
    components.push_back(cur);
  }


  SymExpr res = components[0];
  for (unsigned i = 1; i < sz; ++i) {
    SymExpr cur = components[i];
    res = ConcatExpr::create(cur, res);
  }

//  SymExpr res = ReadExpr::create(ul,
//                                   klee::ConstantExpr::alloc(0,Expr::Int32));
//  for (unsigned i = 1; i < sz; ++i) {
//    SymExpr cur = ReadExpr::create(ul,
//                                     klee::ConstantExpr::alloc(i,Expr::Int32));
//    res = ConcatExpr::create(cur, res);
//  }

  return res;
}

SymExpr PreconditionFixpo::invalidatePtrs(const Value* ptr, SymExpr cond) {
  std::map<SymExpr, SymExpr> eqs;
  std::vector<SymExpr> memsyms = getConstrainedMemSym(cond);

  for (const auto &sym : memsyms) {
    const Value *ldPtr = getPtrForMemSym(sym);
    if (pa.alias(ldPtr, ptr)) {
      SymExpr replacement = generateSymbol(sym->getWidth(), TEMP_SYM);
      eqs.insert({sym, replacement});
    }
  }

  return transferCondWithAssigns(cond, eqs);
}

/// make symbol for val un-constrained in cond
SymExpr PreconditionFixpo::invalidateValueInCond(const Value* val, SymExpr cond) {
  if (isValueTracked(val)) {
    SymExpr sym = getSymForValue(val);
    SymExpr replacement = generateSymbol(sym->getWidth(), TEMP_SYM);
    return transferCondWithAssign(cond, sym, replacement);
  } else {
    return cond;
  }
}

/// For instruction x = expr, where x is a tracked variable, expr is not tracked by the analysis
/// The precondition transformer will make x unconstrained before this instruction
SymExpr PreconditionFixpo::replaceLHSWithUnknownTemp(const Instruction &I, SymExpr cond) {
  SymExpr lhsExp = getSymForValue(&I);
  SymExpr rhsExp = generateSymbol(lhsExp->getWidth(), TEMP_SYM);

  return transferCondWithAssign(cond, lhsExp, rhsExp);
}

SymExpr PreconditionFixpo::transferBinaryArithInst(const Instruction &I, SymExpr cond) {
  assert(isValueTracked(&I));
  auto OpC = I.getOpcode();
  SymExpr rhsExp;
  assert(OpC == Instruction::Add || OpC == Instruction::Sub || OpC == Instruction::Mul
     || OpC == Instruction::SDiv || OpC == Instruction::UDiv || OpC == Instruction::SRem
     || OpC == Instruction::URem);

  if ((!isValueTracked(I.getOperand(0))) || (!isValueTracked(I.getOperand(1)))) {
    /// possible: %192 = sub i64 %191, ptrtoint ([394 x i8*]* @htmlStartClose to i64), !dbg !12669
    return replaceLHSWithUnknownTemp(I, cond);
  }

  SymExpr lhsExp = getSymForValue(&I);
  SymExpr op1Exp = getSymForValue(I.getOperand(0));
  SymExpr op2Exp = getSymForValue(I.getOperand(1));
  if (OpC == Instruction::Add) {
    rhsExp = AddExpr::create(op1Exp, op2Exp);
  } else if (OpC == Instruction::Sub) {
    rhsExp = SubExpr::create(op1Exp, op2Exp);
  } else if (OpC == Instruction::Mul) {
    rhsExp = MulExpr::create(op1Exp, op2Exp);
  } else if (OpC == Instruction::SDiv) {
    rhsExp = SDivExpr::create(op1Exp, op2Exp);
  } else if (OpC == Instruction::UDiv) {
    rhsExp = UDivExpr::create(op1Exp, op2Exp);
  } else if (OpC == Instruction::SRem) {
    rhsExp = SRemExpr::create(op1Exp, op2Exp);
  } else {
    assert(OpC == Instruction::URem);
    rhsExp = URemExpr::create(op1Exp, op2Exp);
  }

  return transferCondWithAssign(cond, lhsExp, rhsExp);
}

SymExpr PreconditionFixpo::transferBinaryBitwiseInst(const Instruction &I, SymExpr cond) {
  assert(isValueTracked(&I));
  auto OpC = I.getOpcode();
  SymExpr rhsExp;
  assert(OpC == Instruction::Shl || OpC == Instruction::LShr ||
         OpC == Instruction::AShr || OpC == Instruction::And ||
         OpC == Instruction::Or || OpC == Instruction::Xor);

  SymExpr lhsExp = getSymForValue(&I);
  SymExpr op1Exp = getSymForValue(I.getOperand(0));
  SymExpr op2Exp = getSymForValue(I.getOperand(1));

  if (OpC == Instruction::Shl) {
    rhsExp = ShlExpr::create(op1Exp, op2Exp);
  } else if (OpC == Instruction::LShr) {
    rhsExp = LShrExpr::create(op1Exp, op2Exp);
  } else if (OpC == Instruction::AShr) {
    rhsExp = AShrExpr::create(op1Exp, op2Exp);
  } else if (OpC == Instruction::And) {
    rhsExp = AndExpr::create(op1Exp, op2Exp);
  } else if (OpC == Instruction::Or) {
    rhsExp = OrExpr::create(op1Exp, op2Exp);
  } else {
    assert(OpC == Instruction::Xor);
    rhsExp = XorExpr::create(op1Exp, op2Exp);
  }

  return transferCondWithAssign(cond, lhsExp, rhsExp);
}

SymExpr PreconditionFixpo::transferComparisonInst(const Instruction &I, SymExpr cond) {
  assert(I.getOpcode() == Instruction::ICmp);
  assert(isValueTracked(&I));

  /// It is possible for icmp to compare pointers, which are not tracked
  if (!isValueTracked(I.getOperand(0)) || !isValueTracked(I.getOperand(1))) {
    return cond;
  }

  SymExpr lhsExp = getSymForValue(&I);
  SymExpr op1Exp = getSymForValue(I.getOperand(0));
  SymExpr op2Exp = getSymForValue(I.getOperand(1));

  SymExpr rhsExp;
  const ICmpInst *ci = cast<ICmpInst>(&I);
  switch(ci->getPredicate()) {
    case ICmpInst::ICMP_EQ: {
      rhsExp = EqExpr::create(op1Exp, op2Exp);
      break;
    }
    case ICmpInst::ICMP_NE: {
      rhsExp = NeExpr::create(op1Exp, op2Exp);
      break;
    }
    case ICmpInst::ICMP_UGT: {
      rhsExp = UgtExpr::create(op1Exp, op2Exp);
      break;
    }
    case ICmpInst::ICMP_UGE: {
      rhsExp = UgeExpr::create(op1Exp, op2Exp);
      break;
    }
    case ICmpInst::ICMP_ULT: {
      rhsExp = UltExpr::create(op1Exp, op2Exp);
      break;
    }
    case ICmpInst::ICMP_ULE: {
      rhsExp = UleExpr::create(op1Exp, op2Exp);
      break;
    }
    case ICmpInst::ICMP_SGT: {
      rhsExp = SgtExpr::create(op1Exp, op2Exp);
      break;
    }
    case ICmpInst::ICMP_SGE: {
      rhsExp = SgeExpr::create(op1Exp, op2Exp);
      break;
    }
    case ICmpInst::ICMP_SLT: {
      rhsExp = SltExpr::create(op1Exp, op2Exp);
      break;
    }
    case ICmpInst::ICMP_SLE: {
      rhsExp = SleExpr::create(op1Exp, op2Exp);
      break;
    }
    default:{
      assert(false);
    }
  }

  return transferCondWithAssign(cond, lhsExp, rhsExp);
}

/// x = *y
std::vector<SymExpr> PreconditionFixpo::transferLoadInst(const Instruction &I, SymExpr cond) {
  assert(isValueTracked(&I));
  const auto *ldInst = cast<LoadInst> (&I);

  if (!isValueConstrained(ldInst, cond)) {
    return {cond};
  }

  SymExpr lhsExp = getSymForValue(ldInst);
  const Value *ptrVal = ldInst->getPointerOperand();
  auto memSym = getMemSymForPtr(ptrVal);
  auto result = transferCondWithAssign(cond, lhsExp, memSym);
  return {result};
}

/// handle *y = z, needs to be sound.
std::vector<SymExpr> PreconditionFixpo::transferStoreInst(const Instruction &I, SymExpr cond) {
  const auto *stInst = cast<StoreInst> (&I);
  auto stVal = stInst->getValueOperand();

  SymExpr rhs = getSymForValue(stVal);
  const Value *ptrVal = stInst->getPointerOperand();
  std::vector<SymExpr> constrainedMemSyms = getConstrainedMemSym(cond);

  ExprHashSet result;
  result.insert(cond);
  for (const auto &memSym : constrainedMemSyms) {
    const Value *ldPtr = getPtrForMemSym(memSym);
    auto aliasRes = pa.alias(ldPtr, ptrVal);
    if (aliasRes == llvm::NoAlias) {
      continue;
    } else if (aliasRes == llvm::MustAlias) {
      if (memSym->getWidth() != rhs->getWidth()) {
        SymExpr replacement = generateSymbol(memSym->getWidth(), TEMP_SYM);
        SymExpr res = transferCondWithAssign(cond, memSym, replacement);
        result.insert(res);
      } else {
        SymExpr res = transferCondWithAssign(cond, memSym, rhs);
        return {res};
      }
    } else {
      if (memSym->getWidth() != rhs->getWidth()) {
        SymExpr replacement = generateSymbol(memSym->getWidth(), TEMP_SYM);
        SymExpr res = transferCondWithAssign(cond, memSym, replacement);
        result.insert(res);
      } else {
        SymExpr res = transferCondWithAssign(cond, memSym, rhs);
        result.insert(res);
      }
    }
  }

  if (DebugSwitch) {
    llvm::errs() << "Store transfer splits to " << result.size() << " conditions\n";
  }
  if (result.size() > PtsBound) {
    if (DebugSwitch) {
      llvm::errs() << "exceeding bounds! shrinking ...\n";
    }
    while (result.size() > PtsBound) {
      auto iter = result.begin();
      result.erase(iter);
    }
  }

  return std::vector<SymExpr>(result.begin(), result.end());
}

SymExpr PreconditionFixpo::transferGEPInst(const Instruction &I, SymExpr cond) {
  assert(isValueTracked(&I));

  const GetElementPtrInst *gep = cast<GetElementPtrInst>(&I);
  auto TyIterBegin = klee::gep_type_begin(gep);
  auto TyIterEnd = klee::gep_type_end(gep);
  klee::ref<klee::ConstantExpr> constantOffset = klee::ConstantExpr::alloc(0, PointerSizeInBits);
  std::vector< std::pair<unsigned, uint64_t> > indices;

  uint64_t index = 1;
  for (auto ii = TyIterBegin; ii != TyIterEnd; ++ii) {
    if (StructType *st = dyn_cast<StructType>(*ii)) {
      const StructLayout *sl = DL->getStructLayout(st);
      const ConstantInt *ci = cast<ConstantInt>(ii.getOperand());
      uint64_t addend = sl->getElementOffset((unsigned) ci->getZExtValue());
      constantOffset = constantOffset->Add(klee::ConstantExpr::alloc(addend,PointerSizeInBits));
    } else if (const auto set = dyn_cast<SequentialType>(*ii)) {
      uint64_t elementSize = DL->getTypeStoreSize(set->getElementType());
      Value *operand = ii.getOperand();
      if (ConstantInt *c = dyn_cast<ConstantInt>(operand)) {
        klee::ref<klee::ConstantExpr> index = klee::ConstantExpr::alloc(c->getValue())->SExt(PointerSizeInBits);
        klee::ref<klee::ConstantExpr> addend =
            index->Mul(klee::ConstantExpr::alloc(elementSize, PointerSizeInBits));
        constantOffset = constantOffset->Add(addend);
      } else {
        indices.push_back(std::make_pair(index, elementSize));
      }
#if LLVM_VERSION_CODE >= LLVM_VERSION(4, 0)
    } else if (const auto ptr = dyn_cast<PointerType>(*ii)) {
      auto elementSize = DL->getTypeStoreSize(ptr->getElementType());
      auto operand = ii.getOperand();
      if (auto c = dyn_cast<ConstantInt>(operand)) {
        auto index = klee::ConstantExpr::alloc(c->getValue())->SExt(PointerSizeInBits);
        auto addend = index->Mul(klee::ConstantExpr::alloc(elementSize,PointerSizeInBits));
        constantOffset = constantOffset->Add(addend);
      } else {
        indices.push_back(std::make_pair(index, elementSize));
      }
#endif
    } else
      assert("invalid type" && 0);
    index++;
  }


  SymExpr lhsExp = getSymForValue(gep);
  SymExpr base = getSymForValue(gep->getPointerOperand());
  SymExpr rhsExp = base;

  for (auto it = indices.begin(), ie = indices.end(); it != ie; ++it) {
    uint64_t elementSize = it->second;
    SymExpr index = getSymForValue(gep->getOperand(it->first));
    rhsExp = AddExpr::create(rhsExp,
                             MulExpr::create(SExtExpr::create(index, PointerSizeInBits),
                                         klee::ConstantExpr::create(elementSize, PointerSizeInBits)));
  }

  rhsExp = AddExpr::create(rhsExp, constantOffset);

  return transferCondWithAssign(cond, lhsExp, rhsExp);
}

SymExpr PreconditionFixpo::transferCallInst(const Instruction &I, SymExpr cond) {
  assert(I.getOpcode() == Instruction::Call || I.getOpcode() == Instruction::Invoke);
  assert(!icfg.isTrackedCallInst(&I));

  CallSite cs(const_cast<Instruction*>(&I));
  bool overApprox = false;
  if (!isa<DbgInfoIntrinsic>(&I) && !analysisUtil::isObject(&I)) { // e.g., lib fun
    overApprox = true;
  }

  if (overApprox) {
    for (auto argIter = cs.arg_begin(); argIter != cs.arg_end(); ++argIter) {
      Value *arg = *argIter;
      if (arg->getType()->isPointerTy()) {
        cond = invalidatePtrs(arg, cond);
      } else if (arg->getType()->isIntegerTy() && !isa<Constant>(arg)) {
        cond = invalidateValueInCond(arg, cond);
      }
    }

    if (isValueTracked(&I)) {
      /// make the lefthand side symbol unconstrained.
      cond = replaceLHSWithUnknownTemp(I, cond);
    }
  }

  return cond;
}

SymExpr PreconditionFixpo::transferSelectInst(const Instruction &I, SymExpr cond) {
  assert(isValueTracked(&I));
  const SelectInst *inst = cast<SelectInst>(&I);
  assert(isValueTracked(inst->getCondition()) && isValueTracked(inst->getTrueValue()) && isValueTracked(inst->getFalseValue()));

  SymExpr condSym = getSymForValue(inst->getCondition());
  SymExpr trSym = getSymForValue(inst->getTrueValue());
  SymExpr fsSym = getSymForValue(inst->getFalseValue());

  SymExpr rhs = SelectExpr::create(condSym, trSym, fsSym);
  SymExpr lhs = getSymForValue(&I);
  return transferCondWithAssign(cond, lhs, rhs);
}

SymExpr PreconditionFixpo::transferCastInst(const Instruction &I, SymExpr cond) {
  assert(isValueTracked(&I));
  if (!isValueTracked(I.getOperand(0))) { /// e.g fptosi
    return cond;
  }

  auto OpC = I.getOpcode();
  SymExpr lhsExp = getSymForValue(&I);
  SymExpr srcExp = getSymForValue(I.getOperand(0));
  SymExpr rhsExp;

  if (OpC == Instruction::Trunc) {
    rhsExp = ExtractExpr::create(srcExp,
                                 0,
                                 getWidthForType(I.getType()));
  } else if (OpC == Instruction::ZExt) {
    rhsExp = ZExtExpr::create(srcExp,
                              getWidthForType(I.getType()));
  } else if (OpC == Instruction::SExt) {
    rhsExp = SExtExpr::create(srcExp,
                              getWidthForType(I.getType()));
  } else if (OpC == Instruction::IntToPtr) {
    rhsExp = ZExtExpr::create(srcExp, getWidthForType(I.getType()));
  } else if (OpC == Instruction::PtrToInt) {
    rhsExp = ZExtExpr::create(srcExp, getWidthForType(I.getType()));
  } else if (OpC == Instruction::BitCast) {
    rhsExp = srcExp;
  } else {
    assert(0);
  }

  return transferCondWithAssign(cond, lhsExp, rhsExp);
}

SymExpr PreconditionFixpo::transferCondWithAssign(SymExpr cond, SymExpr lhs, SymExpr rhs) const {
  ExprReplaceVisitor Visitor(lhs, rhs);
  SymExpr elimExp = Visitor.visit(cond);

  if (Visitor.errorOccured()) {
    return getFalseCond();
  } else {
    return elimExp;
  }
}

SymExpr PreconditionFixpo::transferCondWithAssigns(SymExpr cond, std::map<SymExpr, SymExpr> eqs) const {
  ExprReplaceVisitor2 Visitor(eqs);
  SymExpr elimExp = Visitor.visit(cond);

  if (Visitor.errorOccured()) {
    return getFalseCond();
  } else {
    return elimExp;
  }
}

/// local transfer; control flow is not handled in this function
std::vector<SymExpr> PreconditionFixpo::transferInstData(const Instruction &I, SymExpr cond) {
  if (cond->isTrue() || cond->isFalse()) {
    return {cond};
  }

  auto OpC = I.getOpcode();

  if (OpC == Instruction::Store) { // void return type, itself is not tracked
    auto stInst = cast<StoreInst> (&I);
    if (isValueTracked(stInst->getValueOperand())) {
      return transferStoreInst(I, cond);
    } else {
      return {cond};
    }
  } else if (OpC == Instruction::Call || OpC == Instruction::Invoke) {
    return {transferCallInst(I, cond)};
  }

  if (!isValueTracked(&I)) {
    return {cond};
  }

  for (unsigned i = 0; i < I.getNumOperands(); ++i) {
    llvm::Value* opnd = I.getOperand(i);
    if (opnd->getType()->isIntegerTy() && !isValueTracked(opnd)) {
      /// There are some gross cases like: %11 = or i1 %10, icmp ne (i64 and (i64 ptrtoint ([0 x i32]* @j
      ///                                                     const_rgb_gray_convert_avx2 to i64), i64 31), i64 0), !dbg !7595
      return {replaceLHSWithUnknownTemp(I, cond)};
    }
  }


  if(OpC == Instruction::Add || OpC == Instruction::Sub || OpC == Instruction::Mul
         || OpC == Instruction::SDiv || OpC == Instruction::UDiv || OpC == Instruction::SRem
         || OpC == Instruction::URem) {
    return {transferBinaryArithInst(I, cond)};
  } else if (OpC == Instruction::Shl || OpC == Instruction::LShr ||
             OpC == Instruction::AShr || OpC == Instruction::And ||
             OpC == Instruction::Or || OpC == Instruction::Xor) {
    return {transferBinaryBitwiseInst(I, cond)};
  } else if (OpC == Instruction::ICmp) {
    return {transferComparisonInst(I, cond)};
  } else if (OpC == Instruction::Load) {
    return transferLoadInst(I, cond);
  } else if (OpC == Instruction::Select) {
    return {transferSelectInst(I, cond)};
  } else if (isa<CastInst>(&I)) {
    return {transferCastInst(I,cond)};
  } else {
    // other untracked inst producing a tracked symbol, such as: i = extractelement <4 x i32> %vec, i32 0
    return {replaceLHSWithUnknownTemp(I, cond)};
  }

}

SymExpr PreconditionFixpo::transferCallRecvToCallee(const Instruction &callI, const Instruction &retI, SymExpr cond) {
  assert(icfg.isTrackedCallInst(&callI));
  if (!isValueTracked(&callI)) {
    return cond;
  }

  const ReturnInst *retInst = cast<ReturnInst>(&retI);
  Value *retVal = retInst->getReturnValue();
  if (!retVal || !isValueTracked(retVal)) { /// due to imprecision of icfg
    return replaceLHSWithUnknownTemp(callI, cond);
  }

  SymExpr csRecv = getSymForValue(&callI);
  SymExpr retSym = getSymForValue(retVal);

  if (csRecv->getWidth() == retSym->getWidth()) {
    return transferCondWithAssign(cond, csRecv, retSym);
  } else { /// due to imprecision of icfg
    return replaceLHSWithUnknownTemp(callI, cond);
  }
}

/// ret --> exit (of fun)
SymExpr PreconditionFixpo::transferRetToExit(const llvm::Instruction &callI, const llvm::Instruction &retI, SymExpr cond) {
  assert(icfg.isTrackedCallInst(&callI));
  const Function *fun = retI.getFunction();
  CallSite cs(const_cast<Instruction*>(&callI));

  std::map<SymExpr, SymExpr> eqs;
  for (unsigned i = 0; i < cs.getNumArgOperands(); ++i) {
    Value *arg = cs.getArgOperand(i);
    if (i < fun->arg_size()) {
      auto paramIter = fun->arg_begin();
      for (unsigned j = 0; j < i; ++j) {
        ++paramIter;
      }
      const Value* param = &*paramIter;
      if (isValueTracked(arg) && isValueTracked(param)) {
        auto argSym = getSymForValue(arg), paramSym = getSymForValue(param);
        if (argSym->getWidth() == paramSym->getWidth()) {
          eqs.insert({argSym, paramSym});
        } else {
          if (DebugSwitch) {
            llvm::errs() << "argument/param width mismatch!!\n";
          }
          SymExpr rhsExp = generateSymbol(argSym->getWidth(), TEMP_SYM);
          eqs.insert({argSym, rhsExp});
        }
      }
    }
  }

  /// replace arguments with formal parameters in cond
  cond = transferCondWithAssigns(cond, eqs);
  /// replace callsite receiver with callee return variable in cond
  cond = transferCallRecvToCallee(callI, retI, cond);

  return cond;
}

/// entry (of fun) --> call
SymExpr PreconditionFixpo::transferEntryToCall(const Instruction &I, const Function* fun, SymExpr cond) {
  assert(icfg.isTrackedCallInst(&I));

  CallSite cs(const_cast<Instruction*>(&I));
  std::map<SymExpr, SymExpr> eqs;
  for (unsigned i = 0; i < cs.getNumArgOperands(); ++i) {
    Value *arg = cs.getArgOperand(i);
    if (i < fun->arg_size()) {
      auto paramIter = fun->arg_begin();
      for (unsigned j = 0; j < i; ++j) {
        ++paramIter;
      }
      const Value* param = &*paramIter;
      if (isValueTracked(arg) && isValueTracked(param)) {
        auto paramSym = getSymForValue(param), argSym = getSymForValue(arg);
        if (paramSym->getWidth() == argSym->getWidth()) {
          eqs.insert({paramSym, argSym});
        } else {
          if (DebugSwitch) {
            llvm::errs() << "argument/param width mismatch!!\n";
          }
          SymExpr rhsExp = generateSymbol(paramSym->getWidth(), TEMP_SYM);
          eqs.insert({paramSym, rhsExp});
        }
      }
    }
  }

  /// replace formal parameters with arguments in cond
  cond = transferCondWithAssigns(cond, eqs);

  return cond;
}

/// intra-cfg edge: src(cond) --> dst
void PreconditionFixpo::transferLocalControl(const std::shared_ptr<ICFGNode> &src, const std::shared_ptr<ICFGNode> &dst, const SymExpr &cond) {
  if (dst->getKind() == ICFGNode::ENTRY_NODE) {
    updateStateOut(dst, cond, nullptr);
    return;
  }

  std::vector<SymExpr> transedConds;
  const BasicBlock *from = src->getInst()->getParent();
  bool enterloop = icfg.isLoopExitBB(from);

  if (enterloop) {
    updateStateOut(dst, cond, nullptr);
    return;
  }

  const Instruction *predBBTI = dst->getInst();
  assert(predBBTI->isTerminator());

//  if (icfg.isLoopBB(from) || icfg.isLoopBB(predBBTI->getParent())) {
//    updateStateOut(dst, cond, nullptr);
//    return;
//  }

  if (const auto *bI = dyn_cast<BranchInst>(predBBTI)) {
    if (bI->isConditional() && isValueTracked(bI->getCondition())) { /// there are cases like br i1 icmp ne (i32 (i32*, void ()*)* @pthread_once, i32 (i32*, void ()*)* null), label %32, label %257, !dbg !202894
      Value *brC = bI->getCondition();
      SymExpr brCondSym = getSymForValue(brC);
      auto tbr = AndExpr::create(cond, brCondSym);
      auto fbr = AndExpr::create(cond, Expr::createIsZero(brCondSym));

//      if (enterloop) {
//        transedConds.push_back(tbr);
//        transedConds.push_back(fbr);
//      } else {
        if (bI->getSuccessor(0) == from) {
          transedConds.push_back(tbr);
        } else {
          assert(bI->getSuccessor(1) == from);
          transedConds.push_back(fbr);
        }
//      }
    }
  } else if (const SwitchInst *sI = dyn_cast<SwitchInst>(predBBTI)) {
    SymExpr finalCond = cond;
    std::set<const ConstantInt *> possibleCaseVals;
    std::set<const ConstantInt *> nonDefaultCaseVals;
    bool loseTrack = false;

    // non-default cases
    for (auto i : sI->cases()) {
      const ConstantInt *caseVal = i.getCaseValue();
      if (!isValueTracked(caseVal)) {
        loseTrack = true;
        break;
      }

      const BasicBlock *caseSuccessor = i.getCaseSuccessor();
      if (caseSuccessor == from) {
        possibleCaseVals.insert(caseVal);
      }
      nonDefaultCaseVals.insert(caseVal);
    }

    Value *swCond = sI->getCondition();
    if (!isValueTracked(swCond)) {
      loseTrack = true;
    }

    if (!loseTrack) {
      SymExpr swCondSym = getSymForValue(swCond);
      if (!possibleCaseVals.empty()) {
        SymExpr caseCond = getFalseCond();
        for (auto cv : possibleCaseVals) {
          SymExpr caseValSym = getSymForValue(cv);
          caseCond = OrExpr::create(caseCond, EqExpr::create(swCondSym, caseValSym));
        }
        finalCond = AndExpr::create(finalCond, caseCond);
      } else {
        assert(sI->getDefaultDest() == from);
        SymExpr defaultCond = getTrueCond();
        for (auto cv : nonDefaultCaseVals) {
          SymExpr caseValSym = getSymForValue(cv);
          defaultCond = AndExpr::create(defaultCond, NeExpr::create(swCondSym, caseValSym));
        }
        finalCond = AndExpr::create(finalCond, defaultCond);
      }
    }

    transedConds.push_back(finalCond);
  }

  if (transedConds.empty()) {
    transedConds.push_back(cond);
  }

  for (const auto &transCond : transedConds) {
    updateStateOut(dst, transCond, nullptr);
  }
}

/// pure syntactical match
static bool isCondSubsumed(const SmallVector<SymExpr, 8> &summary, const SymExpr &cond) {
  if (summary.empty()) {
    return false;
  }
  for (const auto &oldCond : summary) {
    if (oldCond == cond) {
      return true;
    }
  }
  return false;
}

bool PreconditionFixpo::updateStateOut(const std::shared_ptr<ICFGNode> &loc, const SymExpr &cond,
                                       const llvm::BasicBlock *dst) {
  return updateState(loc, cond, true, dst);
}

bool PreconditionFixpo::updateStateIn(const std::shared_ptr<ICFGNode> &loc, const SymExpr &cond) {
  return updateState(loc, cond, false, nullptr);
}

bool PreconditionFixpo::updateState(const std::shared_ptr<ICFGNode> &loc, const SymExpr &cond,
                                    bool isPostCond, const BasicBlock *dst) {
  SmallVector<SymExpr, 8> curSummary;
  if (isPostCond) {
    curSummary = stateOutMap[loc];
  } else {
    curSummary = stateInMap[loc];
  }

  if (dst) {
    assert(isPostCond && loc->getInst()->getOpcode() == Instruction::PHI);
  }

  if (!dst && isCondSubsumed(curSummary, cond)) {
    return false;
  }

  auto &joinedLocs = isPostCond ? joinedLocOut : joinedLocIn;
  if (!joinedLocs.count(loc) && curSummary.size() < JoinBound) {
    if (isPostCond) {
      addPostCond(loc, cond);
      pushProcessList(ProcessItem(loc, cond, dst));
    } else {
      addPreCond(loc, cond);
    }
  } else {
    std::shared_ptr<AbstractState> accumulateState = std::make_shared<AbstractState>(*symbolicAbstract(curSummary[0]));
    if (joinedLocs.count(loc)) { /// loc already joined before
      assert(curSummary.size() == 1);
    } else {
      for (unsigned i = 1; i < curSummary.size(); ++i) {
        std::shared_ptr<AbstractState> abs = symbolicAbstract(curSummary[i]);
        accumulateState->join(*abs);
      }
    }

    std::shared_ptr<AbstractState> absNew = symbolicAbstract(cond);

    if (absNew->isLessOrEqual(*accumulateState)) { /// subsumed
      if (joinedLocs.count(loc)) { /// "combined" already propagated before!
        return false;
      }
    } else {
      if (DebugSwitch) {
        llvm::errs() << "Perform widening!\n";
      }
      accumulateState->widen(*absNew);
    }

    if (accumulateState->IsTop()) {
      if (DebugSwitch)
        llvm::errs() << "shooting to top!\n";
    } else {
      if (DebugSwitch)
        llvm::errs() << "merging meaningful!\n";
    }

    joinedLocs.insert(loc);
    SymExpr combined = symbolicConcretize(accumulateState);
    if (isPostCond) {
      stateOutMap[loc] = {combined};
      /// There could be postconditions heading for different dst blocks merged in "combined"
      /// Thus, the merged condition itself does not have a particular direction!
      pushProcessList(ProcessItem(loc, combined, nullptr));
    } else {
      stateInMap[loc] = {combined};
    }
  }

  return true;
}

void PreconditionFixpo::generateMemSym (const llvm::LoadInst *ldInst) {
  assert(isValueTracked(ldInst));
  unsigned width = getSymForValue(ldInst)->getWidth();

  auto ldPtr = ldInst->getPointerOperand();
  if (ldPtrToMemSym.count(ldPtr)) {
    assert(memKeys.count({ldPtr, width}));
    assert(memSymToLdPtr.count(ldPtrToMemSym.at(ldPtr)));
    return;
  }

  auto sym = generateSymbol(width, MEM_SYM);
  assert(ldPtrToMemSym.insert({ldPtr, sym}).second);
  assert(memKeys.insert({ldPtr, width}).second);
  assert(memSymToLdPtr.insert({sym, ldPtr}).second);
}

void PreconditionFixpo::debugFunc(const std::shared_ptr<ICFGNode> &loc, SymExpr cond, const llvm::BasicBlock *dst) const {
  if (DebugFun == "") {
    return;
  }

  static std::error_code EC;
  static llvm::raw_fd_ostream oss("debugfunc.txt", EC, sys::fs::F_Append);

  auto func = loc->getFunc();
  if (func->getName().str() != DebugFun) {
    return;
  }

  if (loc->getKind() == ICFGNode::NORMAL_NODE) {
    if (loc->getInst()->getPrevNode() && loc->getInst()->getNextNode()) { // only log first/last instruction of a bb
      return;
    }
  }

  llvm::errs() << "Inside function " << DebugFun << "\n";

  if (loc->getKind() == ICFGNode::EXIT_NODE) {
    oss << "[EXIT] " + DebugFun;
  } else if (loc->getKind() == ICFGNode::ENTRY_NODE) {
    oss << "[ENTRY] " + DebugFun;
  } else {
    auto inst = loc->getInst();
    assert(inst);
    if (loc->getKind() == ICFGNode::RET_NODE) {
      oss << "[RET]:";
    } else if (loc->getKind() == ICFGNode::CALL_NODE) {
      oss << "[CALL]:";
    } else {
      oss << "[NORMAL]:";
    }

    unsigned asmLineNum = InstructionDbgInfo::instToLine(inst);
    oss << asmLineNum;
  }

  if (dst) {
    auto inst = &*dst->begin();
    unsigned dstLine = InstructionDbgInfo::instToLine(inst);

    oss << " --> " << dstLine;
  }

  oss << "\n";

  cond->print(oss);

  oss << "\n";

}

void PreconditionFixpo::run() {
  while (!isProcessListEmpty()) {
    auto item = popProcessList();
    auto locNode = item.loc;
    auto postCond = item.postCond;
    auto dstBB = item.dst;

    debugFunc(locNode, postCond, dstBB);
    auto locKind = locNode->getKind();
    if (locKind == ICFGNode::NORMAL_NODE) {
      const Instruction *inst = locNode->getInst();
      assert(inst);
      bool isFirstInstInBB = (inst->getPrevNode() == nullptr);

      if (inst->getOpcode() == Instruction::PHI && isValueTracked(inst)) {
        const SymExpr &phiSym = getSymForValue(inst);
        auto phiInst = cast<PHINode>(inst);

        /*for (unsigned i = 0; i < phiInst->getNumIncomingValues(); ++i) {
          Value *inVal = phiInst->getIncomingValue(i);
          if (!isValueTracked(inVal)) continue;

          BasicBlock *inBB = phiInst->getIncomingBlock(i);
          if (dstBB && dstBB != inBB) {
            continue;
          }

          const SymExpr &inSym = getSymForValue(inVal);
          auto preCond = transferCondWithAssign(postCond, phiSym, inSym);

          for (auto nextIter = locNode->next_begin(), eIter = locNode->next_end(); nextIter != eIter; ++nextIter) {
            auto nextICFGNode = *nextIter;
            assert(nextICFGNode->getFunc() == locNode->getFunc());
            assert(ICFG::isEdgeLegal(locNode, nextICFGNode));

            if (isFirstInstInBB) { /// first phi
              updateStateIn(locNode, preCond);

              assert (!dstBB || dstBB == inBB);
              if (!dstBB) {
                transferLocalControl(locNode, nextICFGNode, preCond);
              } else {
                if (inBB == nextICFGNode->getInst()->getParent()) {
                  transferLocalControl(locNode, nextICFGNode, preCond);
                }
              }
            } else {
              updateStateOut(nextICFGNode, preCond, inBB);
            }
          }

        }*/

        auto getPhiPrecondForBB = [phiInst, this, &phiSym, inst] (const SymExpr &post, const llvm::BasicBlock *bb) {
            Value *inVal = phiInst->getIncomingValueForBlock(bb);
            assert(inVal);

            SymExpr preCond;
            if (isValueTracked(inVal)) {
              const SymExpr &inSym = getSymForValue(inVal);
              preCond = transferCondWithAssign(post, phiSym, inSym);
            } else {
              preCond = replaceLHSWithUnknownTemp(*inst, post);
            }

            return preCond;
        };

        if (isFirstInstInBB) { // first phi
          if (dstBB) {
            SymExpr preCond = getPhiPrecondForBB(postCond, dstBB);
            updateStateIn(locNode, preCond);

            auto nextICFGNode = locNode->findNextNodeInBB(dstBB);
            assert(nextICFGNode);
            transferLocalControl(locNode, nextICFGNode, preCond);
          } else {
            for (auto nextIter = locNode->next_begin(), eIter = locNode->next_end(); nextIter != eIter; ++nextIter) {
              auto nextICFGNode = *nextIter;
              auto nextBB = nextICFGNode->getInst()->getParent();

              SymExpr preCond = getPhiPrecondForBB(postCond, nextBB);
              updateStateIn(locNode, preCond);

              transferLocalControl(locNode, nextICFGNode, preCond);
            }
          }
        } else { // There are a sequence of phis, and this phi inst is not the first one
          auto nextICFGNode = locNode->getSingleNextNode();
          if (dstBB) {
            SymExpr preCond = getPhiPrecondForBB(postCond, dstBB);
            updateStateOut(nextICFGNode, preCond, dstBB);
          } else {
            for (unsigned i = 0; i < phiInst->getNumIncomingValues(); ++i) {
              auto inBB = phiInst->getIncomingBlock(i);
              SymExpr preCond = getPhiPrecondForBB(postCond, inBB);
              updateStateOut(nextICFGNode, preCond, inBB);
            }
          }

        }

      } else {
        std::vector<SymExpr> preConds = transferInstData(*inst, postCond);

        for (const auto &preCond : preConds) {
          if (isFirstInstInBB) {
            updateStateIn(locNode, preCond);
          }

          for (auto nextIter = locNode->next_begin(), eIter = locNode->next_end(); nextIter != eIter; ++nextIter) {
            auto nextICFGNode = *nextIter;
            assert(nextICFGNode->getFunc() == locNode->getFunc());
            assert(ICFG::isEdgeLegal(locNode, nextICFGNode));

            if (isFirstInstInBB) {
              transferLocalControl(locNode, nextICFGNode, preCond);
            } else {
              updateStateOut(nextICFGNode, preCond, nullptr);
            }
          }
        }

      }
    } else if (locKind == ICFGNode::EXIT_NODE) {
      for (auto nextIter = locNode->next_begin(), eIter = locNode->next_end(); nextIter != eIter; ++nextIter) {
        auto nextICFGNode = *nextIter;
        updateStateOut(nextICFGNode, postCond, nullptr);
      }
    } else if (locKind == ICFGNode::ENTRY_NODE) {
      for (auto nextIter = locNode->next_begin(), eIter = locNode->next_end(); nextIter != eIter; ++nextIter) {
        auto nextICFGNode = *nextIter;
        auto cs = cast<ICFGNodeCall> (nextICFGNode.get())->getInst();
        auto fromFun = locNode->getFunc();
        auto transCond = transferEntryToCall(*cs, fromFun, postCond);
        updateStateOut(nextICFGNode, transCond, nullptr);
      }
    } else if (locKind == ICFGNode::RET_NODE) {
      for (auto nextIter = locNode->next_begin(), eIter = locNode->next_end(); nextIter != eIter; ++nextIter) {
        auto nextICFGNode = *nextIter;
        auto retNodes = cast<ICFGNodeExit> (nextICFGNode.get())->getNextNodes();
        // there can be function with no return instruction, e.g., wrapper for exit functions.
        // in such cases, the backward propagation stops

        if (!retNodes.empty()) {
          bool updated = false;
          for (auto &retN : retNodes) {
            const Instruction *retI = retN->getInst();

            auto transCond = transferRetToExit(*locNode->getInst(), *retI, postCond);
            updated |= updateStateOut(nextICFGNode, transCond, nullptr);
          }

        }

      }

      {
        CallSite cs(const_cast<Instruction*>(locNode->getInst()));
        if (cs.getCalledFunction() == locNode->getFunc()) {
          /// The edge between CALL & RET is crucial to handle recursive function.
          /// See IFDS's paper.
          /// FIXME: need implement "isBackedge"
          auto callNode = icfg.getCallNode(locNode->getInst());
          updateStateOut(callNode, postCond, nullptr);
        }
      }

    } else {
      assert(locKind == ICFGNode::CALL_NODE);
      bool isFirstInstInBB = (locNode->getInst()->getPrevNode() == nullptr);
      if (isFirstInstInBB) {
        updateStateIn(locNode, postCond);
      }

      for (auto nextIter = locNode->next_begin(), eIter = locNode->next_end(); nextIter != eIter; ++nextIter) {
        auto nextICFGNode = *nextIter;
        assert(nextICFGNode->getFunc() == locNode->getFunc());
        assert(ICFG::isEdgeLegal(locNode, nextICFGNode));
        if (isFirstInstInBB) {
          transferLocalControl(locNode, nextICFGNode, postCond);
        } else {
          updateStateOut(nextICFGNode, postCond, nullptr);
        }
      }
    }

  }
}

std::unordered_map<const llvm::Function*, PreconditionFixpo::FixpointDisjunctiveResult> PreconditionFixpo::getAnalysisResult() {
  auto isCondUnsat = [this] (const SmallVector<SymExpr, 8> &conds) {
    bool isBottom = true;
    for (const SymExpr &pathCond : conds) {
      std::shared_ptr<AbstractState> abs = symbolicAbstract(pathCond);
      if (!abs->IsBot()) {
        isBottom = false;
        break;
      }
    }

    return isBottom;
  };


  std::unordered_map<const llvm::Function*, PreconditionFixpo::FixpointDisjunctiveResult> res;

  for (auto fun : reachableFuncs) {
    FixpointDisjunctiveResult funRes;
    for (auto bbIter = fun->begin(), eIter = fun->end(); bbIter != eIter; ++bbIter) {
      auto bb = &*bbIter;
      if (bb == targetNode->getInst()->getParent()) {
        continue;
      }

      if (isCondUnsat(stateInMap[getNodePre(&*bb->begin())])) {
        funRes.addUnreachableBB(bb);
        continue;
      }

      for (auto instIter = bb->begin(); instIter != bb->end(); ++instIter) {
        const Instruction *inst = &*instIter;
        auto instNode = getNodePost(inst);
        auto postConds = stateOutMap[instNode];

        std::vector<std::shared_ptr<AbstractState>> absStates;
        for (const SymExpr &pathCond : postConds) {
          std::shared_ptr<AbstractState> abs = symbolicAbstract(pathCond);
          if (!abs->IsBot()) {
            absStates.push_back(abs);
          }
        }
        if (absStates.empty()) continue;

        DisjunctiveIntervalSummary SummaryAtLoc(absStates);
        if (SummaryAtLoc.IsTop()) {
          continue;
        } else {
          funRes.addConditionedBB(bb);
        }

        if (intLLVMVals.count(inst)) {
          DisjunctiveIntervalSummary::APIntBounds bounds;
          bool isTop;
          bounds = SummaryAtLoc.getRangesForVal(inst, isTop);
          if (!isTop) {
            funRes.setValResult(inst, std::move(bounds));
          }
        }

      }
    }

    /// argument's value range at entry (SSA)
    auto funEntryNode = icfg.getEntryNode(fun);
    auto postEntryConds = stateOutMap[funEntryNode];
    std::vector<std::shared_ptr<AbstractState>> absStates;
    for (const SymExpr &pathCond : postEntryConds) {
      std::shared_ptr<AbstractState> abs = symbolicAbstract(pathCond);
      if (!abs->IsBot()) {
        absStates.push_back(abs);
      }
    }

    if (!absStates.empty())  {
      DisjunctiveIntervalSummary SummaryAtLoc(absStates);
      if (!SummaryAtLoc.IsTop()) {
        auto argRange = SummaryAtLoc.getRangesForArgs();
        for (const auto &p : argRange) {
          auto arg = p.first;
          if (cast<Argument>(arg)->getParent() == fun) {
            funRes.addArgRange(arg, p.second);
          }
        }
      }
    }


    res[fun] = funRes;
  }

  return res;
}

SymExpr PreconditionFixpo::symbolicConcretize(std::shared_ptr<AbstractState> abs) {
  if (abs->IsBot()) {
    return getFalseCond();
  }

  SymExpr cond = getTrueCond();

  for (auto iter = abs->val_begin(), eIter = abs->val_end(); iter != eIter; ++iter) {
    const Value *val = iter->first;
    Interval itv = iter->second;
    if (itv.IsTop() || itv.IsBot()) {
      continue;
    }

    SymExpr sym = getSymForValue(val);
    /// FIXME: remember to change to UleExpr if switch to use unsigned intervals
    SymExpr lb = klee::ConstantExpr::alloc(itv.getLB());
    SymExpr ub = klee::ConstantExpr::alloc(itv.getUB());

    cond = AndExpr::create(SleExpr::create(lb, sym), cond);
    cond = AndExpr::create(SleExpr::create(sym, ub), cond);
  }

  for (auto iter = abs->mem_begin(), eIter = abs->mem_end(); iter != eIter; ++iter) {
    auto key = iter->first;
    Interval itv = iter->second;
    if (itv.IsTop() || itv.IsBot()) {
      continue;
    }

    SymExpr sym = getMemSymForPtr(key.first);
    SymExpr lb = klee::ConstantExpr::alloc(itv.getLB());
    SymExpr ub = klee::ConstantExpr::alloc(itv.getUB());

    cond = AndExpr::create(SleExpr::create(lb, sym), cond);
    cond = AndExpr::create(SleExpr::create(sym, ub), cond);
  }

  return cond;
}

bool PreconditionFixpo::isValueConstrained(const llvm::Value *v, klee::ref<klee::Expr> cond) const {
  SymExpr sym = getSymForValue(v);
  return isExprContainSubExpr(cond, sym);
}

std::pair<std::vector<const Value*>, std::vector<SymExpr>> PreconditionFixpo::getConstrainedValSym (SymExpr cond) const {
  std::function <bool (SymExpr)> pred = [this] (const SymExpr &exp) {
      return symToIntVals.count(exp);
  };
  std::vector<SymExpr> constrainedSyms = filterExpr(cond, pred);
  std::vector<const Value*> constrainedVals;

  for (const auto &e : constrainedSyms) {
    auto iter = symToIntVals.find(e);
    constrainedVals.push_back(iter->second);
  }

  return {constrainedVals, constrainedSyms};
}

std::vector<SymExpr> PreconditionFixpo::getConstrainedMemSym (const SymExpr &cond) const {
  std::function <bool (SymExpr)> pred = [this] (const SymExpr &exp) {
    return memSymToLdPtr.count(exp);
  };

  return filterExpr(cond, pred);
}

std::vector<SymExpr> PreconditionFixpo::getConstrainedMemValSym (const SymExpr &cond) const {
  std::function <bool (SymExpr)> pred = [this] (const SymExpr &exp) {
      return memSymToLdPtr.count(exp) || symToIntVals.count(exp);
  };

  return filterExpr(cond, pred);
}

std::shared_ptr<AbstractState> PreconditionFixpo::symbolicAbstract(SymExpr cond) const {
//  llvm::errs() << "Begin symbolic abstract!\n";

  auto iter = condToAbs.find(cond);
  if (iter != condToAbs.end()) {
    return iter->second;
  }

  std::shared_ptr<AbstractState> resAbs = initAbsBot();
  if (rangeComp.isCondUnSat(cond)) {
    condToAbs.insert({cond, resAbs});
    return resAbs;
  }

  std::unordered_map<const llvm::Value*, Interval> valRng;
  std::unordered_map<std::pair<const llvm::Value*, unsigned>, Interval, AbstractState::MemKeyHasher> memRng;
  auto constrainedSyms = getConstrainedMemValSym(cond);

  if (!constrainedSyms.empty()) {
    if (DebugSwitch) {
      llvm::errs() << "Number of constrained symbols: " << constrainedSyms.size() << "\n";
    }
    static unsigned totCnt = 0;
    static unsigned unboundCnt = 0;

    std::vector<std::pair<llvm::APInt, llvm::APInt>> rngs;
    rngs = rangeComp.getRanges(cond, constrainedSyms);

    for (unsigned i = 0; i < constrainedSyms.size(); ++i) {
      Interval itv(rngs[i], true);
      auto sym = constrainedSyms[i];

      //      assert(!itv.IsBot());
      if (itv.IsBot()) { /// FIXME: bugs in range computation
        if (DebugSwitch)
          llvm::errs() << "unexpected bot val!\n";
        continue;
      }

      if (symToIntVals.count(sym)) {
        const Value *val = symToIntVals.find(sym)->second;
        valRng.insert({val, itv});
      } else {
        assert(memSymToLdPtr.count(sym));
        const Value *ldPtr = getPtrForMemSym(sym);
        auto key = std::make_pair(ldPtr, sym->getWidth());
        memRng.insert({key, itv});
      }

      ++totCnt;
      if (!itv.IsTop()) {
//        llvm::errs() << "meaningful interval found " << itv.toStr() << "\n";
      } else {
        ++unboundCnt;
//        llvm::errs() << unboundCnt << " unbound out of " << totCnt << "\n";
      }

    }
  }

  resAbs->set(valRng, memRng);
  condToAbs.insert({cond, resAbs});
  assert(!resAbs->IsBot());

//  llvm::errs() << "End symbolic abstract!\n";
  return resAbs;
}

std::shared_ptr<AbstractState> PreconditionFixpo::initAbsBot() const {
  return std::make_shared<AbstractState>(intLLVMVals, memKeys);
}
