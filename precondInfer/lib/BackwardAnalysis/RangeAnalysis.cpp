#include "RangeAnalysis.h"
#include "klee/SymbolicAbstractInterface.h"
#include <numeric>

using namespace absD;
using namespace klee;
using Interval = RangeAnalysis::Interval;

namespace {
  llvm::cl::opt<bool>
      RelationOpt("use-relation-pattern",
                  llvm::cl::init(true));
  llvm::cl::opt<bool>
      DisableRefine("disable-refine", llvm::cl::init(false));
}

static llvm::APInt smin(const llvm::APInt &x, const llvm::APInt &y) { return x.slt(y) ? x : y;}
static llvm::APInt smax(const llvm::APInt &x, const llvm::APInt &y) { return x.sgt(y) ? x : y;}
static inline bool APINT_SIGNED_LESS(const llvm::APInt &a, const llvm::APInt &b){
  return a.slt(b);
}

RangeAnalysis::RangeAnalysis(const ExprTy &cond) : condition(cond) {
  assert(condition->getWidth() == 1);
}

void RangeAnalysis::analyze() {
  buildChildToParentMap();
  labelBoolean(condition, true);

  while (!wlEmpty()) {
    auto e = popWorklist();
    auto itv = getRange(e);
//    if (RelationOpt) {
//      patternMatch(e);
//    }
    propagateDownwards(e, itv);
    propagateUpwards(e, itv);
  }

}

void RangeAnalysis::patternMatch(const ExprTy &e) {
  auto isCmp = [] (const ExprTy &exp) {
    auto K = exp->getKind();
    return K == Expr::Ult || K == Expr::Ule || K == Expr::Slt || K == Expr::Sle ||
           K == Expr::Ne || K == Expr::Ugt || K == Expr::Uge || K == Expr::Sgt || K == Expr::Sge;
  };

  if (!isCmp(e)) {
    return;
  }

  auto itv = getRange(e);
  if (!isIntervalSingleton(itv)) {
    return;
  }

  if (isIntervalTrue(itv)) {
    patternMatch(e, true);
  } else {
    assert(isIntervalFalse(itv));
    patternMatch(e, false);
  }
}

void RangeAnalysis::patternMatch(const ExprTy &e, bool isTrue) {
  /// precondition: isCmp(e)
  if (hasContradiction() || consideredPatterns.count(e)) {
    return;
  }

  auto isVarOrConst = [] (const ExprTy &exp) {
    auto K = exp->getKind();
    return K == Expr::Read || (K == Expr::Extract && exp->getWidth() == 1)
          || K == Expr::Concat || K == Expr::Constant;
  };

  auto makeCmpExpr = [] (Expr::Kind K, const ExprTy &l, const ExprTy &r) {
    if (K == Expr::Ult) {
      return UltExpr::create(l, r);
    } else if (K == Expr::Ule) {
      return UleExpr::create(l,r);
    } else if (K == Expr::Slt) {
      return SltExpr::create(l,r);
    } else if (K == Expr::Sle) {
      return SleExpr::create(l,r);
    } else {
      std::pair<ExprTy, ExprTy> checkRealPair;

      if (K == Expr::Ne) {
        checkRealPair = {NeExpr::create(l,r), NeExpr::alloc(l,r)};
      } else if (K == Expr::Ugt) {
        checkRealPair = {UgtExpr::create(l,r), UgtExpr::alloc(l,r)};
      } else if (K == Expr::Uge) {
        checkRealPair = {UgeExpr::create(l,r), UgeExpr::alloc(l,r)};
      } else if (K == Expr::Sgt) {
        checkRealPair = {SgtExpr::create(l,r), SgtExpr::alloc(l,r)};
      } else {
        assert(K == Expr::Sge);
        checkRealPair = {SgeExpr::create(l,r), SgeExpr::alloc(l,r)};
      }

      if (checkRealPair.first->isFalse()) {
        return checkRealPair.first;
      } else {
        return checkRealPair.second;
      }
    }
  };

  auto isBinOp = [isVarOrConst] (const ExprTy &exp) {
    if (exp->getKind() == Expr::Add || exp->getKind() == Expr::Sub) {
      auto binExp = cast<BinaryExpr>(exp);
      return isVarOrConst(binExp->left) && isVarOrConst(binExp->right);
    } else {
      return false;
    }
  };

  auto updatePattern = [this] (const ExprTy &e, const Interval &newV) {
    consideredPatterns.insert(e);
    updateRange(e, newV);
  };


  auto cmpKind = isTrue ? e->getKind() : getInversePred(e->getKind());
  auto cmpExp = cast<CmpExpr>(e);
  auto leftOp = cmpExp->left, rightOp = cmpExp->right;
  if (isVarOrConst(leftOp) && isVarOrConst(rightOp)) { // x cmp y
    auto cond1 = makeCmpExpr(cmpKind, SubExpr::create(leftOp, rightOp), ConstantExpr::create(0, leftOp->getWidth()));
    auto cond2 = makeCmpExpr(getRevPred(cmpKind), SubExpr::create(rightOp, leftOp), ConstantExpr::create(0, leftOp->getWidth()));
    if (cond1->isFalse() || cond2->isFalse()) {
      goesToBot = true;
      return;
    }

    updatePattern(cond1, intervalConst(true));
    updatePattern(cond2, intervalConst(true));
  } else if (isVarOrConst(leftOp) && isBinOp(rightOp)) { // x cmp (y op z)
    auto x = leftOp, y = cast<BinaryExpr>(rightOp)->left, z = cast<BinaryExpr>(rightOp)->right;
    ExprTy cond1, cond2, cond3, cond4;
    if (rightOp->getKind() == Expr::Add) { // x cmp (y + z)
      cond1 = makeCmpExpr(cmpKind, SubExpr::create(x, y), z); // (x - y) cmp z
      cond2 = makeCmpExpr(getRevPred(cmpKind), SubExpr::create(y, x), z);

      cond3 = makeCmpExpr(cmpKind, SubExpr::create(x, z), y); // (x-z) cmp y
      cond4 = makeCmpExpr(getRevPred(cmpKind), SubExpr::create(z, x), y);
    } else { // x cmp (y - z)
      assert(rightOp->getKind() == Expr::Sub);
      ExprTy minusZ = SubExpr::create(ConstantExpr::create(0, z->getWidth()), z);
      ExprTy minusX = SubExpr::create(ConstantExpr::create(0, x->getWidth()), x);
      ExprTy minusY = SubExpr::create(ConstantExpr::create(0, y->getWidth()), y);

      cond1 = makeCmpExpr(cmpKind, SubExpr::create(x,y),  minusZ); // (x - y) cmp (-z)
      cond2 = makeCmpExpr(getRevPred(cmpKind), SubExpr::create(y, x), z);
      cond3 = makeCmpExpr(cmpKind, AddExpr::create(x, z), y); // (x+z) cmp y
      cond4 = makeCmpExpr(getRevPred(cmpKind), AddExpr::create(minusX, minusZ), minusY);
    }

    if (cond1->isFalse() || cond2->isFalse() || cond3->isFalse() || cond4->isFalse()) {
      goesToBot = true;
      return;
    }

    updatePattern(cond1, intervalConst(true));
    updatePattern(cond2, intervalConst(true));
    updatePattern(cond3, intervalConst(true));
    updatePattern(cond4, intervalConst(true));
  } else if (isBinOp(leftOp) && isVarOrConst(rightOp)) { // (x op y) cmp z
    auto cond = makeCmpExpr(getRevPred(cmpKind), rightOp, leftOp);
    patternMatch(cond, isTrue);
  }
}

std::pair<llvm::APInt, llvm::APInt> RangeAnalysis::getAPIntBound(const klee::ref<klee::Expr> &e) {
  unsigned width = e->getWidth();
  auto itv = getOrInsertRange(e);
  if (itv.IsBot()) {
    auto topV = intervalTop(width);
    return topV.getBounds();
  } else {
    return itv.getBounds();
  }
}

void RangeAnalysis::buildChildToParentMap() {
  auto linkChildToParent = [this] (const ref<Expr> &Child, const ref<Expr> &Parent) {
      auto Iter = childToParentExprMap.find(Child);
      if (Iter == childToParentExprMap.end()) {
        std::vector<ref<Expr>> ParentsVec;
        ParentsVec.push_back(Parent);
        childToParentExprMap.insert({Child, ParentsVec});
      } else {
        std::vector<ref<Expr>> &ParentsVec = childToParentExprMap[Child];
        if (std::find(ParentsVec.begin(), ParentsVec.end(), Parent) == ParentsVec.end()) {
          ParentsVec.push_back(Parent);
        }
      }
  };

  std::vector<ref<Expr>> Worklist;
  ExprHashSet Visited;
  if (condition->getNumKids()) {
    Worklist.push_back(condition);
  }

  while (!Worklist.empty()) {
    auto expr = Worklist.back();
    Worklist.pop_back();

    if (Visited.count(expr)) {
      continue;
    }

    for (auto I = 0; I != expr->getNumKids(); ++I) {
      /// Child could have duplicate, which we check in linkChildToParent
      /// For example: e= (Ult N0, N0)
      auto Child = expr->getKid(I);
      linkChildToParent(Child, expr);
      if (Child->getNumKids()) {
        Worklist.push_back(Child);
      }
    }

    Visited.insert(expr);
  }
}

void RangeAnalysis::propagateUpwards(const ExprTy &e, const Interval &itv) {
  if (hasContradiction()) {
    return;
  }

  auto iter = childToParentExprMap.find(e);
  if (iter == childToParentExprMap.end()) {
    return;
  }

  for (const auto &parent : iter->second) {
    switch (parent->getKind()) {
      case Expr::Select:
        propagateUptoParent(e, cast<SelectExpr>(parent), itv);
        break;
      case Expr::Concat:
        /// FIXME: CVE-2016-4491, join20, may fail the assert
//        assert(false && "concat should be viewed as a whole");
        break;
      case Expr::Extract:
        propagateUptoParent(e, cast<ExtractExpr>(parent), itv);
        break;
      case Expr::ZExt:
      case Expr::SExt:
        propagateUptoParent(e, cast<CastExpr>(parent), itv);
        break;
      case Expr::Add:
      case Expr::Sub:
      case Expr::Mul:
      case Expr::SDiv:
      case Expr::UDiv:
      case Expr::Shl:
      case Expr::LShr:
      case Expr::AShr:
      case Expr::And:
      case Expr::Or:
      case Expr::Xor:
        propagateUptoParentBinary(e, cast<BinaryExpr>(parent), itv);
        break;
      case Expr::Eq:
      case Expr::Ult:
      case Expr::Ule:
      case Expr::Slt:
      case Expr::Sle:
        propagateUptoParent(e, cast<CmpExpr>(parent), itv);
        break;
      case Expr::Ne:
      case Expr::Ugt:
      case Expr::Uge:
      case Expr::Sgt:
      case Expr::Sge: {
//        assert(false && "non-canonical cmp");
        propagateUptoParent(e, cast<CmpExpr>(parent), itv);
        break;
      }
      default:
        break;
    }
  }
}

void RangeAnalysis::propagateUptoParent(const ExprTy &e, const klee::ref<klee::SelectExpr> &parent, const Interval &itv) {
  auto condV = getOrInsertRange(parent->cond);
  if (isIntervalTop(condV) || isIntervalBot(condV)) {
    return;
  }

  if (isIntervalTrue(condV) && parent->trueExpr == e) {
    updateRange(parent, itv);
  } else if (isIntervalFalse(condV) && parent->falseExpr == e) {
    updateRange(parent, itv);
  }
}

void RangeAnalysis::propagateUptoParent(const ExprTy &e, const klee::ref<klee::CastExpr> &parent, const Interval &itv) {
  assert(parent->getKind() == Expr::SExt || parent->getKind() == Expr::ZExt);
  assert(parent->src == e);
  assert(!itv.IsBot());

  unsigned dstWidth = parent->getWidth();
  unsigned srcWidth = itv.getWidth();

  assert(srcWidth < dstWidth);
  if (itv.IsTop()) {
    updateRange(parent, intervalTop(dstWidth));
  } else {
    if (parent->getKind() == Expr::SExt) {
      Interval parentItv({itv.getLB().sext(dstWidth), itv.getUB().sext(dstWidth)}, true);
      updateRange(parent, parentItv);
    } else { // zext
      if (isCrossingSouthPole(itv)) {
        auto lb = llvm::APInt::getNullValue(srcWidth).zext(dstWidth); //0..ext..0 00..0
        auto ub = llvm::APInt::getMaxValue(srcWidth).zext(dstWidth);  //0..ext..0 11..1
        updateRange(parent, Interval({lb, ub}, true));
      } else {
        // operand is seen as unsigned or signed but does not cross zero.
        Interval parentItv({itv.getLB().zext(dstWidth), itv.getUB().zext(dstWidth)}, true);
        updateRange(parent, parentItv);
      }
    }

  }
}

void RangeAnalysis::propagateUptoParent(const ExprTy &e, const klee::ref<klee::ExtractExpr> &parent, const Interval &itv) {
  /// parent = extract(e, 0, w), itv = range of e
  assert(parent->expr == e && parent->offset == 0);
  assert(e->getWidth() > parent->getWidth());
  assert(!itv.IsBot());

  if (isCrossingSouthPole(itv)) {
    updateRange(parent, intervalTop(parent->getWidth()));
  } else {
    /// eithr negative or positive
    unsigned dstWidth = parent->getWidth();
    auto x = itv.getLB().trunc(dstWidth);
    auto y = itv.getUB().trunc(dstWidth);
    auto lb = smin(x,y), ub = smax(x,y);
    updateRange(parent, Interval({lb, ub}, true));
  }
}

void RangeAnalysis::propagateUptoParentBinary(const ExprTy &e, const klee::ref<klee::BinaryExpr> &parent, const Interval &itv) {
  auto op1 = parent->left, op2 = parent->right;
  ref<Expr> otherOp;
  if (op1 == e) {
    otherOp = op2;
  } else {
    assert(op2 == e);
    otherOp = op1;
  }

  auto otherV = getOrInsertRange(otherOp);
  if (otherV.IsBot() || otherV.IsTop()) {
    return;
  }

  const Interval *op1V = nullptr;
  const Interval *op2V = nullptr;

  op1V = (op1 == e) ? &itv : &otherV;
  op2V = (op1 == e) ? &otherV : &itv;
  Expr::Kind opKind = parent->getKind();

  switch (opKind) {
    case Expr::Add:
      updateRange(parent, itvAdd(*op1V, *op2V));
      break;
    case Expr::Sub:
      updateRange(parent, itvSub(*op1V, *op2V));
      break;
    case Expr::Mul:
      updateRange(parent, itvMul(*op1V, *op2V));
      break;
    case Expr::SDiv:
      updateRange(parent, itvDiv(*op1V, *op2V, true));
      break;
    case Expr::UDiv:
      updateRange(parent, itvDiv(*op1V, *op2V, false));
      break;
    case Expr::Shl:
    case Expr::LShr:
    case Expr::AShr:
      updateRange(parent, itvShift(*op1V, *op2V, opKind));
      break;
    case Expr::And:
    case Expr::Or:
    case Expr::Xor:
      if (parent->getWidth() != 1) {
        updateRange(parent, itvLogical(*op1V, *op2V, opKind));
      }
      break;
    default:
      assert(false && "Wrong binary expr!");
      break;

  }
}

void RangeAnalysis::propagateUptoParent(const ExprTy &e, const klee::ref<klee::CmpExpr> &parent, const Interval &itv) {
  auto op1 = parent->left, op2 = parent->right;
  Expr::Kind pred;
  ref<Expr> otherOp;
  if (op1 == e) {
    otherOp = op2;
    pred = parent->getKind();
  } else {
    assert(op2 == e);
    otherOp = op1;
    pred = getRevPred(parent->getKind());
  }

  /// e pred otherOp
  auto otherV = getOrInsertRange(otherOp);
  if (otherV.IsBot() || otherV.IsTop()) {
    return;
  }

  updateRange(parent, itvCmp(itv, otherV, pred));
}

bool RangeAnalysis::isExprVar(const ExprTy &e) const {
  return e->getKind() == Expr::Concat || e->getKind() == Expr::Read ||
         e->getKind() == Expr::Extract;
}

bool RangeAnalysis::isExprConst(const ExprTy &e) const {
  return e->getKind() == Expr::Constant;
}

void RangeAnalysis::propagateDownwards(const ExprTy &e, const Interval &itv) {
  if (hasContradiction()) {
    return;
  }

  assert(!itv.IsBot());

  switch (e->getKind()) {
  case Expr::Select:
    propagateDowntoKid(cast<SelectExpr>(e), itv);
    break;
  case Expr::Concat:
    propagateDowntoKid(cast<ConcatExpr>(e), itv);
    break;
  case Expr::Extract:
    propagateDowntoKid(cast<ExtractExpr>(e), itv);
    break;
  case Expr::ZExt:
  case Expr::SExt:
    propagateDowntoKid(cast<CastExpr>(e), itv);
    break;
  case Expr::Add:
    propagateDowntoKid(cast<AddExpr>(e), itv);
    break;
  case Expr::Sub:
    propagateDowntoKid(cast<SubExpr>(e), itv);
    break;
  case Expr::And:
    propagateDowntoKid(cast<AndExpr>(e), itv);
    break;
  case Expr::Or:
    propagateDowntoKid(cast<OrExpr>(e), itv);
    break;
  case Expr::Not:
    propagateDowntoKid(cast<NotExpr>(e), itv);
    break;
  case Expr::Eq:
  case Expr::Ult:
  case Expr::Ule:
  case Expr::Slt:
  case Expr::Sle:
    propagateDowntoKid(cast<CmpExpr>(e), itv);
    break;
  case Expr::Ne:
  case Expr::Ugt:
  case Expr::Uge:
  case Expr::Sgt:
  case Expr::Sge: {
//    assert(false && "non-canonical cmp");
    propagateDowntoKid(cast<CmpExpr>(e), itv);
    break;
  }
  default:
    break;
  }

}

Expr::Kind RangeAnalysis::getRevPred(Expr::Kind pred) const {
  static const std::map<Expr::Kind, Expr::Kind> lookup {
      std::make_pair(Expr::Eq, Expr::Eq),
      std::make_pair(Expr::Ne, Expr::Ne),

      std::make_pair(Expr::Ult, Expr::Ugt),
      std::make_pair(Expr::Ugt, Expr::Ult),

      std::make_pair(Expr::Ule, Expr::Uge),
      std::make_pair(Expr::Uge, Expr::Ule),

      std::make_pair(Expr::Slt, Expr::Sgt),
      std::make_pair(Expr::Sgt, Expr::Slt),

      std::make_pair(Expr::Sle, Expr::Sge),
      std::make_pair(Expr::Sge, Expr::Sle),
  };

  return lookup.at(pred);
}

klee::Expr::Kind RangeAnalysis::getInversePred(klee::Expr::Kind pred) const {
  static const std::map<Expr::Kind, Expr::Kind> lookup {
      std::make_pair(Expr::Eq, Expr::Ne),
      std::make_pair(Expr::Ne, Expr::Eq),

      std::make_pair(Expr::Ult, Expr::Uge),
      std::make_pair(Expr::Uge, Expr::Ult),

      std::make_pair(Expr::Ule, Expr::Ugt),
      std::make_pair(Expr::Ugt, Expr::Ule),

      std::make_pair(Expr::Slt, Expr::Sge),
      std::make_pair(Expr::Sge, Expr::Slt),

      std::make_pair(Expr::Sle, Expr::Sgt),
      std::make_pair(Expr::Sgt, Expr::Sle),
  };

  return lookup.at(pred);
}

void RangeAnalysis::propagateDowntoKid(const klee::ref<klee::SelectExpr> &e, const Interval &itv) {
  auto condV = getOrInsertRange(e->cond);
  if (isIntervalTop(condV) || isIntervalBot(condV)) {
    return;
  }

  if (isIntervalTrue(condV)) {
    updateRange(e->trueExpr, itv);
  } else {
    assert(isIntervalFalse(condV));
    updateRange(e->falseExpr, itv);
  }

}

/// Concat expr originates from array read. In current modelling, the array read is viewed as a whole.
/// We never extract bytes over concats. Thus, no need to descend.
void RangeAnalysis::propagateDowntoKid(const klee::ref<klee::ConcatExpr> &e, const Interval &itv) {
  return;
}

///  case 1) symbol for bool (whole symbol)
///  case 2) trunc inst / zext inst
///  must begin at offset 0
void RangeAnalysis::propagateDowntoKid(const klee::ref<klee::ExtractExpr> &e, const Interval &itv) {
  if (e->getWidth() != 1) {
    auto targetV = getOrInsertRange(e->expr);
    auto itvExtend = extendInterval(itv, e->expr->getWidth(), false);
    targetV = refineInterval(targetV, itvExtend, Expr::Uge);
    updateRange(e->expr, targetV);
  }
}

void RangeAnalysis::propagateDowntoKid(const klee::ref<klee::CastExpr> &e, const Interval &itv) {
  assert(e->getKind() == Expr::SExt || e->getKind() == Expr::ZExt);
  auto targetV = getOrInsertRange(e->src);
  auto targetVExtend = extendInterval(targetV, e->getWidth(), false);
  targetVExtend = refineInterval(targetVExtend, itv, Expr::Ule);

  targetV = shrinkInterval(targetVExtend, e->src->getWidth());
  updateRange(e->src, targetV);
}

void RangeAnalysis::propagateDowntoKid(const klee::ref<klee::AddExpr> &e, const Interval &itv) {
  auto op1 = e->left, op2 = e->right;
  if (DisableRefine) {
    if ((isExprVar(op1) && isExprConst(op2)) || (isExprVar(op2) && isExprConst(op1))) {

    } else {
      return;
    }
  }


  auto op1V = getOrInsertRange(op1), op2V = getOrInsertRange(op2);
  if (op1V.IsBot()) {
    op1V = intervalTop(op1->getWidth());
  }

  if (op2V.IsBot()) {
    op2V = intervalTop(op2->getWidth());
  }

  auto op1vv = itvSub(itv, op2V);
  auto op2vv = itvSub(itv, op1V);
  updateRange(op1,op1vv);
  updateRange(op2,op2vv);
}

void RangeAnalysis::propagateDowntoKid(const klee::ref<klee::SubExpr> &e, const Interval &itv) {
  auto op1 = e->left, op2 = e->right;
  if (DisableRefine) {
    if ((isExprVar(op1) && isExprConst(op2)) || (isExprVar(op2) && isExprConst(op1))) {

    } else {
      return;
    }
  }

  auto op1V = getOrInsertRange(op1), op2V = getOrInsertRange(op2);
  if (op1V.IsBot()) {
    op1V = intervalTop(op1->getWidth());
  }

  if (op2V.IsBot()) {
    op2V = intervalTop(op2->getWidth());
  }

  auto op1vv = itvAdd(itv, op2V);
  auto op2vv = itvSub(op1V, itv);
  updateRange(op1,op1vv);
  updateRange(op2,op2vv);
}

void RangeAnalysis::propagateDowntoKid(const klee::ref<klee::NotExpr> &e, const Interval &itv) {
  if (e->getWidth() == 1) {
    if (isIntervalTrue(itv)) {
      updateRange(e->expr, intervalConst(false));
    } else if (isIntervalFalse(itv)) {
      updateRange(e->expr, intervalConst(true));
    }
  }
}

void RangeAnalysis::propagateDowntoKid(const klee::ref<klee::AndExpr> &e, const Interval &itv) {
  if (e->getWidth() == 1) {
    if (isIntervalTrue(itv)) {
      updateRange(e->left, intervalConst(true));
      updateRange(e->right, intervalConst(true));
    }
  }
}

void RangeAnalysis::propagateDowntoKid(const klee::ref<klee::OrExpr> &e, const Interval &itv) {
  if (e->getWidth() == 1) {
    if (isIntervalFalse(itv)) {
      updateRange(e->left, intervalConst(false));
      updateRange(e->right, intervalConst(false));
    }
  }
}

void RangeAnalysis::propagateDowntoKid(const klee::ref<klee::CmpExpr> &e, const Interval &itv) {
  auto op1 = e->left;
  auto op2 = e->right;

  if (DisableRefine) {
    if ((isExprVar(op1) && isExprConst(op2)) || (isExprVar(op2) && isExprConst(op1))) {

    } else {
      return;
    }
  }

  if (isIntervalTop(itv)) {
    return;
  }

  if (isUnInit(op1) && isUnInit(op2)) { // both are bots
    return;
  }

  auto pred = e->getKind();
  auto revPred = getRevPred(pred);

  if (isIntervalFalse(itv)) {
    pred = getInversePred(pred);
    revPred = getRevPred(pred);
  } else {
    assert(isIntervalTrue(itv) && "itv can not be bottom!");
  }

  auto op1V = getOrInsertRange(op1), op2V = getOrInsertRange(op2);
  auto op1vv = refineInterval(op1V, op2V, pred);
  auto op2vv = refineInterval(op2V, op1V, revPred);

  updateRange(op1, op1vv);
  updateRange(op2, op2vv);
}

Interval RangeAnalysis::itvSub(const Interval &I1, const Interval &I2) const {
  assert(!I1.IsBot() && !I2.IsBot());
  Interval res(I1);
  bool OverflowLB, OverflowUB;
  res.setLB(I1.getLB().ssub_ov(I2.getUB(),OverflowLB));
  res.setUB(I1.getUB().ssub_ov(I2.getLB(),OverflowUB));
  if (OverflowLB || OverflowUB) {
    return intervalTop(I1.getWidth());
  } else {
    return res;
  }
}

Interval RangeAnalysis::itvAdd(const Interval &I1, const Interval &I2) const {
  assert(!I1.IsBot() && !I2.IsBot());
  Interval res(I1);
  bool OverflowLB, OverflowUB;
  res.setLB(I1.getLB().sadd_ov(I2.getLB(),OverflowLB));
  res.setUB(I1.getUB().sadd_ov(I2.getUB(),OverflowUB));
  if (OverflowLB || OverflowUB) {
    return intervalTop(I1.getWidth());
  } else {
    return res;
  }
}

Interval RangeAnalysis::itvMul(const Interval &I1, const Interval &I2) const {
  assert(!I1.IsBot() && !I2.IsBot());
  llvm::APInt a,b,c,d;
  bool Overflow1,Overflow2,Overflow3,Overflow4;
  a = I1.getLB().smul_ov(I2.getLB(),Overflow1);
  b = I1.getLB().smul_ov(I2.getUB(),Overflow2);
  c = I1.getUB().smul_ov(I2.getLB(),Overflow3);
  d = I1.getUB().smul_ov(I2.getUB(),Overflow4);

  if (Overflow1 || Overflow2 || Overflow3 || Overflow4) {
    return intervalTop(I1.getWidth());
  } else {
    Interval res(I1);
    res.setLB(smin(smin(smin(a,b),c),d));
    res.setUB(smax(smax(smax(a,b),c),d));
    return res;
  }
}

Interval RangeAnalysis::itvDiv(const Interval &I1, const Interval &I2, bool isSignedOp) const {
  assert(!I1.IsBot() && !I2.IsBot());
  using namespace llvm;
  bool isOverflow = false;
  std::vector<Interval> res = purgeZero(I2);
  if (res.empty()) {
    // dived by zero occurs.
    return intervalTop(I1.getWidth());
  }

  APInt a = I1.getLB();
  APInt b = I1.getUB();

  std::vector<APInt> extremes;
  for (const auto &divisor : res) {
    APInt c = divisor.getLB();
    APInt d = divisor.getUB();
    if (isSignedOp) {
      APInt e1 = a.sdiv_ov(c,isOverflow);
      if (isOverflow){
        return intervalTop(I1.getWidth());
      }
      extremes.push_back(e1);

      APInt e2 = a.sdiv_ov(d,isOverflow);
      if (isOverflow){
        return intervalTop(I1.getWidth());
      }
      extremes.push_back(e2);

      APInt e3 = b.sdiv_ov(c,isOverflow);
      if (isOverflow){
        return intervalTop(I1.getWidth());
      }
      extremes.push_back(e3);

      APInt e4 = b.sdiv_ov(d,isOverflow);
      if (isOverflow){
        return intervalTop(I1.getWidth());
      }
      extremes.push_back(e4);
    } else{
      extremes.push_back(a.udiv(c));
      extremes.push_back(a.udiv(d));
      extremes.push_back(b.udiv(c));
      extremes.push_back(b.udiv(d));
    }
  }

  Interval resItv(I1);
  resItv.setLB(*std::min_element(extremes.begin(), extremes.end(),
                                 APINT_SIGNED_LESS));
  resItv.setUB(*std::max_element(extremes.begin(), extremes.end(),
                                 APINT_SIGNED_LESS));

  return resItv;
}

/// I1 << I2
Interval RangeAnalysis::itvShift(const Interval &I1, const Interval &I2, Expr::Kind opCode) const {
  assert(!I1.IsBot() && !I2.IsBot());
  using namespace llvm;
  if (I2.IsTop()) {
    return intervalTop(I1.getWidth());
  }

  if (!isIntervalSingleton(I2)) {
    return intervalTop(I1.getWidth());
  }

  auto shift = getIntervalSingleton(I2);
  if ((!shift.isNegative()) && shift.slt(I1.getWidth()) && shift.getBitWidth() <= 64) {
    APInt a = I1.getLB();
    APInt b = I1.getUB();

    if (opCode == Expr::Shl) {
      if (I1.IsTop()) {
        return I1;
      }
      // The implementation of APInt::sshl_ov does not allow change of signedness bit(otherwise
      //  Overflow flag will be set)
      bool IsOverflow1, IsOverflow2;
      auto lb = a.sshl_ov(shift, IsOverflow1);
      auto ub = b.sshl_ov(shift, IsOverflow2);
      if (IsOverflow1 || IsOverflow2) {
        return intervalTop(I1.getWidth());
      } else {
        return Interval({lb,ub}, true);
      }
    } else if (opCode == Expr::LShr) {
      if (I1.IsTop() || isCrossingSouthPole(I1)) {
        // 0^{w}
        auto lb = APInt::getNullValue(a.getBitWidth());
        // 0^{k}1^{w-k}
        auto ub = APInt::getLowBitsSet(a.getBitWidth(),a.getBitWidth() - shift.getZExtValue());

        return Interval({lb,ub}, true);
      } else {
        /// lies entirely in the positive or negative range
        return Interval({a.lshr(shift), b.lshr(shift)}, true);
      }
    } else {
      assert(opCode == Expr::AShr);
      return Interval({a.ashr(shift), b.ashr(shift)}, true);
    }
  } else {
    return intervalTop(I1.getWidth());
  }
}

Interval RangeAnalysis::itvLogical(const Interval &I1, const Interval &I2, klee::Expr::Kind opCode) const {
  assert(!I1.IsBot() && !I2.IsBot());
  if (I1.IsTop() && I2.IsTop()) {
    return intervalTop(I1.getWidth());
  }

  if (opCode == Expr::Or) {
    return itvOr(I1, I2);
  } else if (opCode == Expr::And) {
    return itvAnd(I1, I2);
  } else {
    assert(opCode == Expr::Xor);
    return itvXor(I1, I2);
  }
}

namespace {
  using namespace llvm;
  int64_t minOr_int64t(int64_t a, int64_t b, int64_t c, int64_t d) {
    int64_t m, temp;
    m = 0x80000000;
    while (m != 0) {
      if (~a & c & m) {
        temp = (a | m) & -m;
        if (temp <= b) {
          a = temp;
          break;
        }
      }
      else if (a & ~c & m) {
        temp = (c | m) & -m;
        if (temp <= d) {
          c = temp;
          break;
        }
      }
      m = m >> 1;
    }
    return a | c;
  }

  int64_t maxOr_int64t(int64_t a, int64_t b, int64_t c, int64_t d){
    int64_t m, temp;

    m = 0x80000000;
    while (m != 0) {
      if (b & d & m) {
        temp = (b - m) | (m - 1);
        if (temp >= a) {
          b = temp;
          break;
        }
        temp = (d - m) | (m - 1);
        if (temp >= c) {
          d = temp;
          break;
        }
      }
      m = m >> 1;
    }
    return b | d;
  }

  APInt
  minOr(const APInt &a, const APInt &b, const APInt &c, const APInt &d) {
    APInt res(a.getBitWidth(),
              minOr_int64t(a.getSExtValue(), b.getSExtValue(),
                           c.getSExtValue(), d.getSExtValue()));
    return res;
  }

  APInt
  maxOr(const APInt &a, const APInt &b, const APInt &c, const APInt &d){
    APInt res(a.getBitWidth(),
              maxOr_int64t(a.getSExtValue(), b.getSExtValue(),
                           c.getSExtValue(), d.getSExtValue()));
    return res;
  }

  APInt
  minAnd(APInt a, const APInt &b, APInt c, const APInt &d) {
    APInt m =   APInt::getOneBitSet(a.getBitWidth(), a.getBitWidth()-1);
    while (m != 0){
      if ((~a & ~c & m).getBoolValue()){
        APInt temp = (a | m) &  ~m;
        if (temp.ule(b)){
          a = temp;
          break;
        }
        temp = (c | m) & ~m;
        if (temp.ule(d)){
          c = temp;
          break;
        }
      }
      m = m.lshr(1);
    }
    return a & c;
  }

  APInt
  maxAnd(const APInt &a, APInt b, const APInt &c, APInt d) {
    APInt m =   APInt::getOneBitSet(a.getBitWidth(), a.getBitWidth()-1);
    while (m != 0){
      if ((b & ~d & m).getBoolValue()){
        APInt temp = (b & ~m) | (m - 1);
        if (temp.uge(a)){
          b = temp;
          break;
        }
      }
      else{
        if ((~b & d & m).getBoolValue()){
          APInt temp = (d & ~m) | (m - 1);
          if (temp.uge(c)){
            d = temp;
            break;
          }
        }
      }
      m = m.lshr(1);
    }
    return b & d;
  }

  Interval unsignedAnd (const Interval &I1, const Interval &I2) {
    APInt a = I1.getLB();
    APInt b = I1.getUB();
    APInt c = I2.getLB();
    APInt d = I2.getUB();

    auto lb = minAnd(a,b,c,d);
    auto ub = maxAnd(a,b,c,d);
    return Interval({lb, ub}, true);
  }


  APInt
  minXor(const APInt &a, const APInt &b, const APInt &c, const APInt &d){
    return (minAnd(a,b,~d,~c) | minAnd(~b,~a,c,d));
  }

  APInt
  maxXor(const APInt &a, const APInt &b, const APInt &c, const APInt &d){
    return (maxOr(APInt::getNullValue(a.getBitWidth()),
                        maxAnd(a,b,~d,~c),
                        APInt::getNullValue(a.getBitWidth()),
                        maxAnd(~b,~a,c,d)));
  }

  Interval unsignedXor (const Interval &I1, const Interval &I2) {
    APInt a = I1.getLB();
    APInt b = I1.getUB();
    APInt c = I2.getLB();
    APInt d = I2.getUB();

    auto lb = minXor(a, b, c, d);
    auto ub = maxXor(a, b, c, d);
    return Interval({lb, ub}, true);
  }
}


Interval RangeAnalysis::itvOr(const Interval &I1, const Interval &I2) const {
  using namespace llvm;
  APInt a = I1.getLB();
  APInt b = I1.getUB();
  APInt c = I2.getLB();
  APInt d = I2.getUB();

  unsigned width = a.getBitWidth();

  unsigned char case_val = 0;
  case_val += (a.isNonNegative() ? 1 : 0);
  case_val <<= 1;
  case_val += (b.isNonNegative() ? 1 : 0);
  case_val <<= 1;
  case_val += (c.isNonNegative() ? 1 : 0);
  case_val <<= 1;
  case_val += (d.isNonNegative() ? 1 : 0);

  APInt lb, ub;
  switch (case_val) {
    case 0: // - - - -
      lb = minOr(a, b, c, d);
      ub = maxOr(a, b, c, d);
      break;
    case 1: // - - - +
      lb = a;
      ub = APInt(width, -1, true);
      break;
    case 3: // - - + +
      lb = minOr(a, b, c, d);
      ub = maxOr(a, b, c, d);
      break;
    case 4: // - + - -
      lb = c;
      ub = APInt(width, -1, true);
      break;
    case 5: // - + - +
      lb = smin(a,c);
      ub = maxOr(APInt::getNullValue(width), b,
                 APInt::getNullValue(width), d);
      break;
    case 7: // - + + +
      lb = minOr(a, ~APInt::getNullValue(width), c, d);
      ub = maxOr(APInt::getNullValue(width), b, c, d);
      break;
    case 12: // + + - -
      lb = minOr(a, b, c, d);
      ub = maxOr(a, b, c, d);
      break;
    case 13: // + + - +
      lb = minOr(a, b, c, ~APInt::getNullValue(width) );
      ub = maxOr(a, b, APInt::getNullValue(width), d);
      break;
    case 15: // + + + +
      lb = minOr(a, b, c, d);
      ub = maxOr(a, b, c, d);
      break;
    default:
      assert(false && "This should not happen");
  }

  return Interval({lb,ub}, true);
}

Interval RangeAnalysis::itvAnd(const Interval &I1, const Interval &I2) const {
  std::vector<Interval> s1 = ssplit(I1);
  std::vector<Interval> s2 = ssplit(I2);
  auto res = intervalBottom(I1.getWidth());

  for (const auto &itv1 : s1) {
    for (const auto &itv2 : s2) {
      res.join(unsignedAnd(itv1, itv2));
    }
  }

  return res;
}

Interval RangeAnalysis::itvXor(const Interval &I1, const Interval &I2) const {
  std::vector<Interval> s1 = ssplit(I1);
  std::vector<Interval> s2 = ssplit(I2);
  auto res = intervalBottom(I1.getWidth());

  for (const auto &itv1 : s1) {
    for (const auto &itv2 : s2) {
      res.join(unsignedXor(itv1, itv2));
    }
  }

  return res;
}

Interval RangeAnalysis::itvCmp(const Interval &I1, const Interval &I2, klee::Expr::Kind cmpPred) const {
  using namespace llvm;
  assert(!I1.IsBot() && !I2.IsBot());
  if (I1.IsTop() || I2.IsTop()) {
    return intervalTop(1);
  }

  auto cmpLess = [this] (const Interval &lhs, const Interval &rhs, bool isStrict, bool isSignedOp) {
    APInt a = lhs.getLB(), b = lhs.getUB(), c = rhs.getLB(), d = rhs.getUB();

    if (isSignedOp) {
      if ((isStrict && b.slt(c)) || (!isStrict && b.sle(c))) {
        return intervalConst(true);
      }

      if ((isStrict && a.sge(d)) || (!isStrict && a.sgt(d))) {
        return intervalConst(false);
      }

      return intervalTop(1); // unknown
    } else {
      if ((isStrict && b.ult(c)) || (!isStrict && b.ule(c))) {
        return intervalConst(true);
      }

      if ((isStrict && a.uge(d)) || (!isStrict && a.ugt(d))) {
        return intervalConst(false);
      }

      return intervalTop(1); // unknown
    }
  };


  APInt a = I1.getLB(), b = I1.getUB(), c = I2.getLB(), d = I2.getUB();
  if (std::set<Expr::Kind>{Expr::Eq, Expr::Ult, Expr::Ule, Expr::Slt, Expr::Sle}.count(cmpPred)) {
    if (cmpPred == Expr::Eq) {
      if (isIntervalSingleton(I1) && I1.getBounds() == I2.getBounds()) { // true
        return intervalConst(true);
      }
      Interval res(I1); res.meet(I2);
      if (res.IsBot()) { // false
        return intervalConst(false);;
      }

      return intervalTop(1); // unknown
    } else if (cmpPred == Expr::Ult || cmpPred == Expr::Ule) {
      bool isStrict = (cmpPred == Expr::Ult);
      auto lhsSubItvs = ssplit(I1);
      auto rhsSubItvs = ssplit(I2);

      std::vector<Interval> candidates;

      for (const auto &lItv : lhsSubItvs) {
        for (const auto &rItv : rhsSubItvs) {
          candidates.push_back(cmpLess(lItv, rItv, isStrict, false));
        }
      }

      auto resItv = std::accumulate(std::next(candidates.begin()), candidates.end(),
                               candidates[0], [] (const Interval &I1, const Interval &I2) {
                      Interval res(I1);
                      res.join(I2);
                      return res;
                    });

      return resItv;
    } else {
      assert(cmpPred == Expr::Slt || cmpPred == Expr::Sle);
      return cmpLess(I1, I2, cmpPred == Expr::Slt, true);
    }
  } else {
    auto check = std::set<Expr::Kind>{Expr::Eq, Expr::Ugt, Expr::Uge, Expr::Sgt, Expr::Sge}.count(cmpPred);
    assert(check);
    return itvCmp(I2, I1, getRevPred(cmpPred));
  }

}


void RangeAnalysis::pushWorklist(const ExprTy &e) {
  worklist.insert(e);
}

RangeAnalysis::ExprTy RangeAnalysis::popWorklist() {
  assert(!wlEmpty());
  auto iter = worklist.begin();
  auto elem = *iter;
  worklist.erase(iter);
  return elem;
}

void RangeAnalysis::labelBoolean(const ExprTy &cond, bool label) {
  assert(cond->getWidth() == 1);
  if (hasContradiction()) {
    return;
  }

  updateRange(cond, intervalConst(label));

  switch(cond->getKind()) {
  case Expr::Constant:
    break;
  case Expr::And: {
    if (label) {
      auto be = cast<BinaryExpr> (cond);
      labelBoolean(be->left, label);
      labelBoolean(be->right, label);
    }
    break;
  }
  case Expr::Or: {
    if (!label) {
      auto be = cast<BinaryExpr> (cond);
      labelBoolean(be->left, label);
      labelBoolean(be->right, label);
    }
    break;
  }
  case Expr::Not: {
    auto ne = cast<NotExpr>(cond);
    labelBoolean(ne->expr, !label);
    break;
  }

  case Expr::Xor:
  case Expr::Eq:
  case Expr::Slt:
  case Expr::Sle:
  case Expr::Ult:
  case Expr::Ule:
    break;
  case Expr::Extract:
    break;
  case Expr::Select:
    /// cases such as (Select (Eq N0:(ReadLSB w32 0 int_48738)
    //                         N1:(ReadLSB w32 0 int_48740))
    //                         (Slt (ReadLSB w32 0 int_48736) (ReadLSB w32 0 int_48737)) (Slt N0 N1))
    break;
  default:
    assert(false && "unknown bool expr");

  }
}

Interval RangeAnalysis::intervalConst(const llvm::APInt &v) const {
  return Interval ({v,v}, true);
}

Interval RangeAnalysis::intervalConst(int64_t v, unsigned w) const {
  return intervalConst(llvm::APInt(w,v));
}

Interval RangeAnalysis::intervalConst(bool c) const {
  return intervalConst(c, 1);
}

Interval RangeAnalysis::intervalTop(unsigned w) const {
  return Interval::createTop(w, true);
}

Interval RangeAnalysis::intervalBottom(unsigned w) const {
  return Interval::createBottom(w, true);
}

bool RangeAnalysis::isIntervalSingleton(const Interval &itv) const {
  auto bounds = itv.getBounds();
  return bounds.first == bounds.second;
}

llvm::APInt RangeAnalysis::getIntervalSingleton(const Interval &itv) const {
  assert(isIntervalSingleton(itv));
  return itv.getBounds().first;
}

bool RangeAnalysis::isIntervalTrue(const Interval &itv) const {
  assert(itv.getWidth() == 1);
  if (isIntervalSingleton(itv)) {
    return getIntervalSingleton(itv).getBoolValue();
  } else {
    return false;
  }
}

bool RangeAnalysis::isIntervalFalse(const BackwardAI::Interval &itv) const {
  assert(itv.getWidth() == 1);
  if (isIntervalSingleton(itv)) {
    return !getIntervalSingleton(itv).getBoolValue();
  } else {
    return false;
  }
}

bool RangeAnalysis::isIntervalTop(const Interval &itv) const {
  return itv.IsTop();
}

bool RangeAnalysis::isIntervalBot(const Interval &itv) const {
  return itv.IsBot();
}

Interval RangeAnalysis::refineInterval(const Interval &lhs, const Interval &rhs, klee::Expr::Kind cmpPred) const {
  assert(lhs.getWidth() == rhs.getWidth());
  if (lhs.IsBot()) {
    return refineInterval(intervalTop(lhs.getWidth()), rhs, cmpPred);
  }

  if (rhs.IsTop() || rhs.IsBot()) {
    return lhs;
  }

  if (cmpPred == Expr::Eq) {
    Interval resItv = lhs;
    resItv.meet(rhs);
    return resItv;
  }

  if (cmpPred == Expr::Ne) {
    if (isIntervalSingleton(rhs)) {
      Interval resItv = lhs;
      auto val = getIntervalSingleton(rhs);
      if (lhs.getLB() == val) {
        resItv.setLB(val+1);
      }
      if (lhs.getUB() == val) {
        resItv.setUB(val-1);
      }
      return resItv;
    } else {
      return lhs;
    }
  }

  if (std::set<Expr::Kind>{Expr::Ult, Expr::Ule, Expr::Slt, Expr::Sle}.count(cmpPred)) {
    return refineIntervalLess(lhs, rhs, cmpPred);
  } else {
    auto predCheck = std::set<Expr::Kind>{Expr::Ugt, Expr::Uge, Expr::Sgt, Expr::Sge}.count(cmpPred);
    assert(predCheck);
    return refineIntervalMore(lhs, rhs, cmpPred);
  }
}

Interval RangeAnalysis::refineIntervalLess(const Interval &lhs, const Interval &rhs, Expr::Kind cmpPred) const {
  assert(!lhs.IsBot() && !rhs.IsBot());

  auto refineLess = [this] (const Interval &I1, const Interval &I2, bool isSignedOp, bool isStrict) {
    llvm::APInt a = I1.getLB();
    llvm::APInt b = I1.getUB();
    llvm::APInt c = I2.getLB();
    llvm::APInt d = I2.getUB();


    bool isBot = isStrict ? Interval::range_ge(a, d, isSignedOp) : Interval::range_gt(a, d, isSignedOp);

    if (isBot) { // The relation must not hold
      return intervalBottom(I1.getWidth());
    }

    Interval resItv = I1;
    resItv.meet(I2);

    if (resItv.IsBot()) { // The relation must hold, e.g. [0,2] < [10,50]
      return I1;
    }

    llvm::APInt refined_d = isStrict ? d - 1 : d;

    resItv.setLB(a); // set back I1's lower bound
    if(Interval::range_le(d, b, isSignedOp)) {
      resItv.setUB(refined_d);
    }

    return resItv;
  };


  Interval resItv = lhs;

  if (cmpPred == Expr::Slt || cmpPred == Expr::Sle) { // apply signed comparison
    resItv = refineLess(lhs, rhs, true, cmpPred == Expr::Slt);
  } else { // Applying unsigned comparison on signed intervals
    assert(cmpPred == Expr::Ult || cmpPred == Expr::Ule);
    std::vector<Interval> lhsItvs = ssplit(lhs);
    std::vector<Interval> rhsItvs = ssplit(rhs);
    std::vector<Interval> candidates;

    for (const auto &lItv : lhsItvs) {
      for (const auto &rItv : rhsItvs) {
        candidates.push_back(refineLess(lItv, rItv, false, cmpPred == Expr::Ult));
      }
    }

    resItv = std::accumulate(std::next(candidates.begin()), candidates.end(),
                      candidates[0], [] (const Interval &I1, const Interval &I2) {
      Interval res(I1);
      res.join(I2);
      return res;
    });

  }

  return resItv;
}

Interval RangeAnalysis::refineIntervalMore(const Interval &lhs, const Interval &rhs, klee::Expr::Kind cmpPred) const {
  assert(!lhs.IsBot() && !rhs.IsBot());

  auto refineMore = [this] (const Interval &I1, const Interval &I2, bool isSignedOp, bool isStrict) {
    llvm::APInt a = I1.getLB();
    llvm::APInt b = I1.getUB();
    llvm::APInt c = I2.getLB();
    llvm::APInt d = I2.getUB();

    bool isBot = isStrict ? Interval::range_le(b, c, isSignedOp) : Interval::range_lt(b, c, isSignedOp);

    if (isBot) { // The relation must not hold
      return intervalBottom(I1.getWidth());
    }

    Interval resItv = I1;
    resItv.meet(I2);

    if (resItv.IsBot()) { // The relation must hold, e.g. [10,50] > [0,2];
      return I1;
    }

    llvm::APInt refined_c = isStrict ? c+1 : c;

    resItv.setUB(b); // set back I1's upper bound
    if(Interval::range_le(a, c, isSignedOp)) {
      resItv.setLB(refined_c);
    }

    return resItv;
  };


  Interval resItv = lhs;

  if (cmpPred == Expr::Sgt || cmpPred == Expr::Sge) { // apply signed comparison
    resItv = refineMore(lhs, rhs, true, cmpPred == Expr::Sgt);
  } else { // Applying unsigned comparison on signed intervals
    assert(cmpPred == Expr::Ugt || cmpPred == Expr::Uge);
    std::vector<Interval> lhsItvs = ssplit(lhs);
    std::vector<Interval> rhsItvs = ssplit(rhs);
    std::vector<Interval> candidates;

    for (const auto &lItv : lhsItvs) {
      for (const auto &rItv : rhsItvs) {
        candidates.push_back(refineMore(lItv, rItv, false, cmpPred == Expr::Ugt));
      }
    }

    resItv = std::accumulate(std::next(candidates.begin()), candidates.end(),
                             candidates[0], [] (const Interval &I1, const Interval &I2) {
            Interval res(I1);
            res.join(I2);
            return res;
        });

  }

  return resItv;
}

void RangeAnalysis::updateRange(const ExprTy &e, const Interval &newV) {
  //auto oldV = getOrInsertRange(e);
  //auto itv = oldV;
  //itv.join(newV);
  //assert(oldV.isLessOrEqual(itv));
  //setRange(e, itv);

  //goesToBot = itv.IsBot();
  //if (!goesToBot && oldV.getBounds() != itv.getBounds()) {
  //  pushWorklist(e);
  //}

  auto oldV = getOrInsertRange(e);
  if (oldV.IsBot()) { /// e has an undefined bottom value, we encounter its first update.
    goesToBot = newV.IsBot();
    if (!goesToBot) {
      setRange(e, newV);
      pushWorklist(e);
    }
  } else { /// e already has some meaningful value
    auto itv = oldV;
    itv.meet(newV);
    assert(itv.isLessOrEqual(oldV));

    goesToBot = itv.IsBot();
    if (!goesToBot && oldV.getBounds() != itv.getBounds()) {
      setRange(e, itv);
      pushWorklist(e);
    }
  }
}

Interval RangeAnalysis::getRange(const ExprTy &e) const {
  return result.find(e)->second;
}

void RangeAnalysis::setRange(const ExprTy &e, const Interval &itv) {
  auto iter = result.find(e);
  if (iter == result.end()) {
    result.insert({e,itv});
  } else {
    iter->second = itv;
  }
}

bool RangeAnalysis::isUnInit(const ExprTy &e) const {
  if (isa<klee::ConstantExpr> (e)) {
    return false;
  } else {
    return !result.count(e);
  }
}

Interval RangeAnalysis::getOrInsertRange(const ExprTy &e) {
  auto iter = result.find(e);
  if (iter == result.end()) {
    if (isa<ConstantExpr>(e)) {
      auto itv = intervalConst(cast<ConstantExpr>(e)->getAPValue());
      result.insert({e, itv});
      return itv;
    } else {
      auto itv = intervalBottom(e->getWidth());
      result.insert({e, itv});
      return itv;
    }
  } else {
    return iter->second;
  }
}

bool RangeAnalysis::isCrossingSouthPole(const Interval &itv) const {
  unsigned width = itv.getWidth();
  llvm::APInt spLB = llvm::APInt::getMaxValue(width); // 111...1
  llvm::APInt spUB(width, 0); // 000...0
  Interval southPole({spLB, spUB}, true);
  return southPole.isLessOrEqual(itv);
}

std::vector<Interval> RangeAnalysis::ssplit(const Interval &itv) const {
  unsigned width = itv.getWidth();
  llvm::APInt spLB = llvm::APInt::getMaxValue(width); // 111...1
  llvm::APInt spUB(width, 0); // 000...0
  Interval southPole({spLB, spUB}, true);
  if (southPole.isLessOrEqual(itv)) {
    Interval I1({itv.getLB(), spLB}, true); // [x, 111....1]
    Interval I2({spUB, itv.getUB()}, true); // [000...0,  y]
    return {I1, I2};
  } else {
    return {itv};
  }
}

std::vector<Interval> RangeAnalysis::purgeZero(const Interval &itv) const {
  assert(!itv.IsBot());
  using namespace llvm;
  unsigned width = itv.getWidth();
  std::vector<Interval> res;

  Interval zero({APInt(width, 0), APInt(width, 0)}, true);
  if (zero.isLessOrEqual(itv)) {
    if (!isIntervalSingleton(itv)) {
      if (itv.getLB() == 0) {
        res.push_back(Interval({itv.getLB()+1, itv.getUB()}, true));
      } else {
        if (itv.getUB() == 0) {
          APInt minusOne = APInt::getMaxValue(width); // 111...1
          res.push_back(Interval({itv.getLB(), minusOne}, true)); // [x, 111....1]
        } else {
          APInt plusOne(width, 1);          // 000...1
          APInt minusOne = APInt::getMaxValue(width); // 111...1
          Interval I1({itv.getLB(), minusOne}, true); // [x, 111....1]
          Interval I2({plusOne, itv.getUB()}, true); // [000...1,  y]
          res.push_back(I1);
          res.push_back(I2);
        }
      }
    }
  } else {
    res.push_back(itv);
  }

  return res;
}

Interval RangeAnalysis::extendInterval(const Interval &itv, unsigned w, bool isSignExt) const {
  assert(itv.getWidth() <= w);

  if (itv.IsTop()) {
    return intervalTop(w);
  }

  if (itv.IsBot()) {
    return intervalBottom(w);
  }

  if (itv.getWidth() == w) {
    return itv;
  }

  auto lb = itv.getLB();
  auto ub = itv.getUB();

  if (isSignExt) {
    return Interval({lb.sext(w), ub.sext(w)}, true);
  } else {
    unsigned srcWidth = itv.getWidth();
    unsigned dstWidth = w;
    if (isCrossingSouthPole(itv)) {
      auto lbNew = llvm::APInt::getNullValue(srcWidth).zext(dstWidth); //0..ext..0 00..0
      auto ubNew = llvm::APInt::getMaxValue(srcWidth).zext(dstWidth);  //0..ext..0 11..1
      return Interval({lbNew, ubNew}, true);
    } else {
      // operand is seen as unsigned or signed but does not cross zero.
      return Interval({itv.getLB().zext(dstWidth), itv.getUB().zext(dstWidth)}, true);
    }
  }
}

Interval RangeAnalysis::shrinkInterval(const Interval &itv, unsigned w) const {
  assert(itv.getWidth() >= w);

  if (itv.IsTop()) {
    return intervalTop(w);
  }

  if (itv.IsBot()) {
    return intervalBottom(w);
  }

  if (itv.getWidth() == w) {
    return itv;
  }

  auto lb = itv.getLB();
  auto ub = itv.getUB();

  if (lb.getMinSignedBits() <= w && ub.getMinSignedBits() <= w) {
    return Interval({lb.trunc(w), ub.trunc(w)}, true);
  } else {
    return intervalTop(w);
  }
}

RangeCompute::RangeCompute(const klee::ref<klee::Expr> &cond) {
  impl = new RangeAnalysis(cond);
  impl->analyze();
  isUnsat = impl->hasContradiction();
}

bool RangeCompute::isCondUnSat() {
  return isUnsat;
}

std::pair<llvm::APInt, llvm::APInt> RangeCompute::getRange(const klee::ref<klee::Expr> &sym) {
  return impl->getAPIntBound(sym);
}

std::vector<std::pair<llvm::APInt, llvm::APInt>> RangeCompute::getRanges(const std::vector<klee::ref<klee::Expr>> &syms) {
  std::vector<std::pair<llvm::APInt, llvm::APInt>> res;
  for (const auto &sym : syms) {
    auto bounds = impl->getAPIntBound(sym);
    assert(bounds.first.getBitWidth() == bounds.second.getBitWidth());
    assert(bounds.first.getBitWidth() == sym->getWidth());
    res.push_back(bounds);
  }
  return res;
}

RangeCompute::~RangeCompute() {
  delete impl;
}
