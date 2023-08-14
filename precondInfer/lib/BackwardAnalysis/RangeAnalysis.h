#ifndef RANGE_ANALYSIS_H
#define RANGE_ANALYSIS_H
#include "klee/Expr.h"
#include "klee/util/ExprHashMap.h"
#include "AbstractState.h"

namespace absD {
  class RangeAnalysis {
  public:
    using Interval = BackwardAI::Interval;
    using ExprTy = klee::ref<klee::Expr>;

    RangeAnalysis(const ExprTy &cond);
    void analyze();
    bool hasContradiction() const {
      return goesToBot;
    }

    std::pair<llvm::APInt, llvm::APInt> getAPIntBound(const klee::ref<klee::Expr> &e);
  private:
    ExprTy condition;
    klee::ExprHashMap<Interval> result;
    klee::ExprHashSet consideredPatterns;
    klee::ExprHashSet worklist;
    mutable bool goesToBot = false;
    klee::ExprHashMap<std::vector<klee::ref<klee::Expr>>> childToParentExprMap;

    void patternMatch(const ExprTy &e);
    void patternMatch(const ExprTy &e, bool isTrue);

    void pushWorklist(const ExprTy &e);
    ExprTy popWorklist();

    bool wlEmpty() const {
      return worklist.empty();
    }

    void buildChildToParentMap();

    void labelBoolean(const ExprTy &cond, bool label);
    /// opearions on interval
    Interval intervalConst(const llvm::APInt &v) const;
    Interval intervalConst(int64_t v, unsigned w) const;
    Interval intervalConst(bool cond) const;
    Interval intervalTop(unsigned) const;
    Interval intervalBottom(unsigned) const;
    bool isIntervalSingleton(const Interval &itv) const;
    llvm::APInt getIntervalSingleton(const Interval &itv) const;
    bool isIntervalTrue(const Interval &itv) const;
    bool isIntervalFalse(const Interval &itv) const;
    bool isIntervalTop(const Interval &itv) const;
    bool isIntervalBot(const Interval &itv) const;
    Interval refineIntervalLess(const Interval &lhs, const Interval &rhs, klee::Expr::Kind cmpPred) const;
    Interval refineIntervalMore(const Interval &lhs, const Interval &rhs, klee::Expr::Kind cmpPred) const;
    Interval refineInterval(const Interval &lhs, const Interval &rhs, klee::Expr::Kind cmpPred) const;

    std::vector<Interval> ssplit(const Interval &itv) const;
    std::vector<Interval> purgeZero(const Interval &itv) const;
    bool isCrossingSouthPole(const Interval &itv) const;
    Interval extendInterval(const Interval &itv, unsigned w, bool isSignExt) const;
    Interval shrinkInterval(const Interval &itv, unsigned w) const;
    Interval itvSub(const Interval &I1, const Interval &I2) const;
    Interval itvAdd(const Interval &I1, const Interval &I2) const;
    Interval itvMul(const Interval &I1, const Interval &I2) const;
    Interval itvDiv(const Interval &I1, const Interval &I2, bool isSignedOp) const;
    Interval itvShift(const Interval &I1, const Interval &I2, klee::Expr::Kind opCode) const;
    Interval itvLogical(const Interval &I1, const Interval &I2, klee::Expr::Kind opCode) const;
    Interval itvOr(const Interval &I1, const Interval &I2) const;
    Interval itvAnd(const Interval &I1, const Interval &I2) const;
    Interval itvXor(const Interval &I1, const Interval &I2) const;
    Interval itvCmp(const Interval &I1, const Interval &I2, klee::Expr::Kind cmpPred) const;

    void updateRange(const ExprTy &e, const Interval &newV);
    Interval getRange(const ExprTy &e) const;
    void setRange(const ExprTy &e, const Interval &itv);
    bool isUnInit(const ExprTy &e) const;
    Interval getOrInsertRange(const ExprTy &e);

    bool isExprVar(const ExprTy &e) const;
    bool isExprConst(const ExprTy &e) const;

    void propagateDownwards(const ExprTy &e, const Interval &itv);

    klee::Expr::Kind getRevPred(klee::Expr::Kind pred) const;
    klee::Expr::Kind getInversePred(klee::Expr::Kind pred) const;

    void propagateDowntoKid(const klee::ref<klee::SelectExpr> &e, const Interval &itv);
    void propagateDowntoKid(const klee::ref<klee::ConcatExpr> &e, const Interval &itv);
    void propagateDowntoKid(const klee::ref<klee::ExtractExpr> &e, const Interval &itv);
    void propagateDowntoKid(const klee::ref<klee::CastExpr> &e, const Interval &itv);
    void propagateDowntoKid(const klee::ref<klee::AddExpr> &e, const Interval &itv);
    void propagateDowntoKid(const klee::ref<klee::SubExpr> &e, const Interval &itv);
    void propagateDowntoKid(const klee::ref<klee::NotExpr> &e, const Interval &itv);
    void propagateDowntoKid(const klee::ref<klee::AndExpr> &e, const Interval &itv);
    void propagateDowntoKid(const klee::ref<klee::OrExpr> &e, const Interval &itv);
    void propagateDowntoKid(const klee::ref<klee::CmpExpr> &e, const Interval &itv);

    void propagateUpwards(const ExprTy &e, const Interval &itv);
    void propagateUptoParent(const ExprTy &e, const klee::ref<klee::SelectExpr> &parent, const Interval &itv);
    /// parent can never be concat or extract expr. We view them as a whole, thus their sub expressions can never update.
    void propagateUptoParent(const ExprTy &e, const klee::ref<klee::CastExpr> &parent, const Interval &itv);
    void propagateUptoParent(const ExprTy &e, const klee::ref<klee::ExtractExpr> &parent, const Interval &itv);
    void propagateUptoParentBinary(const ExprTy &e, const klee::ref<klee::BinaryExpr> &parent, const Interval &itv);
    void propagateUptoParent(const ExprTy &e, const klee::ref<klee::CmpExpr> &parent, const Interval &itv);

  };
}
#endif