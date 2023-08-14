#include "AbstractState.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/DerivedTypes.h"
#include <functional>
#include <numeric>
#include <iterator>

using namespace BackwardAI;
using namespace klee;
using namespace llvm;

Interval::Interval(std::pair<llvm::APInt, llvm::APInt> bounds, bool isSigned)
: isSigned(isSigned), bounds(std::move(bounds)) {
  assert(bounds.first.getBitWidth() == bounds.second.getBitWidth());
  /// FIXME: can not call normalize here, will trigger infinite recursion. Should be fine, check all external Interval construction calls :)
}

Interval::Interval(const Interval &rhs)
  : isSigned(rhs.isSigned), bounds(rhs.bounds) {}

Interval& Interval::operator=(const Interval &rhs) {
  sanityCheck(rhs);
  assignRhs(rhs);
  return *this;
}

Interval Interval::createBottom(unsigned w, bool isSigned) {
  APInt lb = getMaxVal(w, isSigned);
  APInt ub = getMinVal(w, isSigned);
  Interval res = Interval({lb, ub}, isSigned);
  assert(res.IsBot());
  return res;
}

/// canonical rep for bottom
void Interval::normalize() {
  if (IsBot()) {
    Interval bot = createBottom(getWidth(), isSigned);
    *this = bot;
  }
}

Interval Interval::createTop(unsigned w, bool isSigned) {
  APInt lb = getMinVal(w, isSigned);
  APInt ub = getMaxVal(w, isSigned);

  return Interval({lb, ub}, isSigned);
}


void Interval::widen(const Interval &rhs) {
  sanityCheck(rhs);
  if (IsBot() || rhs.IsTop()) {
    assignRhs(rhs);
    return;
  }

  if (IsTop() || rhs.IsBot()) {
    return;
  }

  APInt lb = getLB(), ub = getUB(), rlb = rhs.getLB(), rub = rhs.getUB();

  if (range_lt(rlb, lb, isSigned)) {
    lb = getMinVal(lb.getBitWidth(), isSigned);
  }

  if (range_gt(rub, ub, isSigned)) {
    ub = getMaxVal(ub.getBitWidth(), isSigned);
  }

  setLB(lb);
  setUB(ub);
}

void Interval::join(const Interval &rhs) {
  sanityCheck(rhs);
  if (IsBot() || rhs.IsTop()) {
    assignRhs(rhs);
    return;
  }

  if (IsTop() || rhs.IsBot()) {
    return;
  }

  APInt lb = getLB(), ub = getUB(), rlb = rhs.getLB(), rub = rhs.getUB();

  lb = range_le(lb, rlb, isSigned) ? lb : rlb;
  ub = range_ge(ub, rub, isSigned) ? ub : rub;

  setLB(lb);
  setUB(ub);
}

void Interval::meet(const Interval &rhs) {
  sanityCheck(rhs);
  if (IsTop() || rhs.IsBot()) {
    assignRhs(rhs);
    return;
  }

  if (rhs.IsTop() || IsBot()) {
    return;
  }

  APInt lb = getLB(), ub = getUB(), rlb = rhs.getLB(), rub = rhs.getUB();
  lb = range_le(lb, rlb, isSigned) ? rlb : lb;
  ub = range_ge(ub, rub, isSigned) ? rub : ub;

  setLB(lb);
  setUB(ub);

  normalize();
}

bool Interval::hasIntersection(Interval lhs, Interval rhs) {
  lhs.meet(rhs);
  return !lhs.IsBot();
}

bool Interval::isLessOrEqual(const Interval &rhs) const {
  sanityCheck(rhs);
  if (IsBot()) return true;
  if (IsTop()) return rhs.IsTop();
  if (rhs.IsBot()) return IsBot();
  if (rhs.IsTop()) return  true;

  APInt lb = getLB(), ub = getUB(), rlb = rhs.getLB(), rub = rhs.getUB();

  return range_ge(lb, rlb, isSigned) && range_le(ub, rub, isSigned);
}

std::string Interval::toStr() const {
  if (IsBot()) return "bottom";
  if (IsTop()) return "top";

  if (isSigned) {
    auto lb = getLB().getSExtValue();
    auto ub = getUB().getSExtValue();
    return "[" + std::to_string(lb) + "," + std::to_string(ub) + "]";
  } else {
    auto lb = getLB().getZExtValue();
    auto ub = getUB().getZExtValue();
    return "[" + std::to_string(lb) + "," + std::to_string(ub) + "]";
  }
}

bool Interval::range_le(const llvm::APInt &lhs, const llvm::APInt &rhs, bool isSigned) {
  if (isSigned) return lhs.sle(rhs);
  else return lhs.ule(rhs);
}

bool Interval::range_lt(const llvm::APInt &lhs, const llvm::APInt &rhs, bool isSigned) {
  if (isSigned) return lhs.slt(rhs);
  else return lhs.ult(rhs);
}

bool Interval::range_ge(const llvm::APInt &lhs, const llvm::APInt &rhs, bool isSigned) {
  if (isSigned) return lhs.sge(rhs);
  else return lhs.uge(rhs);
}

bool Interval::range_gt(const llvm::APInt &lhs, const llvm::APInt &rhs, bool isSigned) {
  if (isSigned) return lhs.sgt(rhs);
  else return lhs.ugt(rhs);
}

APInt Interval::getMinVal(unsigned w, bool isSigned) {
  return isSigned ? APInt::getSignedMinValue(w) : APInt::getMinValue(w);
}

APInt Interval::getMaxVal(unsigned w, bool isSigned) {
  return isSigned ? APInt::getSignedMaxValue(w) : APInt::getMaxValue(w);
}

Interval AbstractState::getRangeForValue(const llvm::Value *v) const {
  if (IsBot()) {
    return Interval::createBottom(v->getType()->getIntegerBitWidth(), true);
  }

  if (valRng.count(v)) {
    return valRng.at(v);
  }

  assert(valKeys.count(v));
  return Interval::createTop(v->getType()->getIntegerBitWidth(), true);
}

Interval AbstractState::getRangeForMem(std::pair<const llvm::Value*, unsigned> key) const {
  if (IsBot()) {
    return Interval::createBottom(key.second, true);
  }

  if (memRng.count(key)) {
    return memRng.at(key);
  }

  assert(memKeys.count(key));
  return Interval::createTop(key.second, true);
}


bool AbstractState::IsBot() const {
  return valRng.empty() && memRng.empty();
}

bool AbstractState::IsTop() const {
  if (IsBot())  return false;
  for (auto iter = valRng.begin(); iter != valRng.end(); ++iter) {
    if (!iter->second.IsTop()) {
      return false;
    }
  }

  for (auto iter = memRng.begin(); iter != memRng.end(); ++iter) {
    if (!iter->second.IsTop()) {
      return false;
    }
  }

  return true;
}

void AbstractState::assignRhs(const AbstractState &rhs) {
  valRng = rhs.valRng;
  memRng = rhs.memRng;
}

void AbstractState::set(decltype(valRng) valRange, decltype(memRng) memRange) {
  assert(IsBot());
  /// no meaningful values. We want the abstract state to be top!
  /// Add in a place holder to differentiate with the bottom case.
  if (valRange.empty() && memRange.empty()) {
    const Value *placeHodler = *valKeys.begin();
    valRng.insert({placeHodler, Interval::createTop(placeHodler->getType()->getIntegerBitWidth(), true)});
  } else {
    /// caller needs to make sure that valRange & memRange does not contain bottom interval
    valRng = std::move(valRange);
    memRng = std::move(memRange);
  }
}

void AbstractState::join(const AbstractState &rhs) {
  if (rhs.IsBot()) {
    return;
  }

  if (IsBot()) {
    assignRhs(rhs);
    return;
  }

  /// If a val key is present in rhs, but not in *this*, then
  /// *this* has top for val already, no need to join.
  for (auto &valRange : valRng) {
    const Value *val = valRange.first;
    auto &range = valRange.second;
    range.join(rhs.getRangeForValue(val));
  }

  for (auto &objWidthRange : memRng) {
    auto key = objWidthRange.first;
    auto &range = objWidthRange.second;
    range.join(rhs.getRangeForMem(key));
  }

}

void AbstractState::widen(const AbstractState &rhs) {
  if (rhs.IsBot()) {
    return;
  }

  if (IsBot()) {
    assignRhs(rhs);
    return;
  }

  for (auto &valRange : valRng) {
    const Value *val = valRange.first;
    auto &range = valRange.second;
    range.widen(rhs.getRangeForValue(val));
  }

  for (auto &objWidthRange : memRng) {
    auto key = objWidthRange.first;
    auto &range = objWidthRange.second;
    range.widen(rhs.getRangeForMem(key));
  }
}

bool AbstractState::isLessOrEqual(const AbstractState &rhs) const {
  if (IsBot()) {
    return true;
  }

  for (auto iter = valRng.begin(); iter != valRng.end(); ++iter) {
    const Value *val = iter->first;
    if (getRangeForValue(val).isLessOrEqual(rhs.getRangeForValue(val)) == false) {
      return false;
    }
  }

  for (auto &objWidthRange : memRng) {
    auto key = objWidthRange.first;
    if (getRangeForMem(key).isLessOrEqual(rhs.getRangeForMem(key)) == false) {
      return false;
    }
  }

  for (const auto &valRngPair : rhs.valRng) {
    const Value *val = valRngPair.first;
    if (!valRng.count(val)) { /// this has top value
      auto itv = valRngPair.second;
      if (!itv.IsTop()) {
        return false;
      }
    }
  }

  for (auto &objWidthRange : rhs.memRng) {
    auto key = objWidthRange.first;
    if (!memRng.count(key)) { /// this has top value
      auto itv = objWidthRange.second;
      if (!itv.IsTop()) {
        return false;
      }
    }
  }

  return true;
}

DisjunctiveIntervalSummary::DisjunctiveIntervalSummary (const std::vector<std::shared_ptr<AbstractState>> states) {
  std::vector<std::set<const Value *>> valKeysSets;
  for (const auto &abs : states) {
    std::set<const Value *> valKeys;
    for (auto iter = abs->val_begin(), eIter = abs->val_end(); iter != eIter; ++iter) {
      const Value *val = iter->first;
      valKeys.insert(val);
    }
    valKeysSets.push_back(valKeys);
  }

  assert(!valKeysSets.empty());

  // Compute values that are present (not necessarily top) in all states
  std::set<const Value *> sharedKeys =
    std::accumulate(std::next(valKeysSets.begin()), valKeysSets.end(), valKeysSets[0],
                  [] (const std::set<const Value *> &l, const std::set<const Value *> &r) {
                      std::set<const Value *> sharedKeys;
                      std::set_intersection(l.begin(),l.end(),r.begin(),r.end(),
                                       std::inserter(sharedKeys, sharedKeys.begin()));
                      return sharedKeys;
  });

  for (auto val : sharedKeys) {
    summary[val].push_back(states[0]->accessRangeForValue(val));
  }

  for (size_t i = 1; i < states.size(); ++i) {
    for (auto val : sharedKeys) {
      DisjunctiveInterval &s = summary.at(val);
      s = addToDisjointIntervals(s, states[i]->accessRangeForValue(val));
    }
  }
}

/// invariant: maintain a disjunction of normal intervals or one sinlge bottom value.
DisjunctiveIntervalSummary::DisjunctiveInterval DisjunctiveIntervalSummary::addToDisjointIntervals(
    const DisjunctiveIntervalSummary::DisjunctiveInterval &s, Interval itv) {
  assert(!s.empty());

  if (itv.IsTop()) { // quick prune path
    DisjunctiveInterval res;
    res.push_back(itv);
    return res;
  }

  if (itv.IsBot()) {
    return s;
  }

  DisjunctiveInterval intersectItvs;
  DisjunctiveInterval disjointItvs;

  for (auto &r : s) {
    if (Interval::hasIntersection(r, itv)) { /// r can not be bot here
      intersectItvs.push_back(r);
    } else {
      if (!r.IsBot()) {
        disjointItvs.push_back(r);
      }
    }
  }

  DisjunctiveInterval res;
  Interval mergedR = std::accumulate(intersectItvs.begin(), intersectItvs.end(), itv,
                             [] (Interval r1, Interval r2) {
    r1.join(r2);
    return r1;
  });

  res.push_back(mergedR);
  res.insert(res.end(), disjointItvs.begin(), disjointItvs.end());

  std::sort(res.begin(), res.end(), [] (const Interval &l, const Interval &r) {
    return l.getLB().getSExtValue() < r.getLB().getSExtValue();
  });

  /// res should be non-empty and containt no bottom val
  assert(res.size() >= 1);

  /// combine neighbour endpoints of intervals
  std::vector<DisjunctiveInterval> foldContainer;
  std::transform(res.begin(), res.end(), std::back_inserter(foldContainer), [](const Interval &itv) {
    assert(!itv.IsBot());
    DisjunctiveInterval singleton;
    singleton.push_back(itv);
    return singleton;
  });

  DisjunctiveInterval foldedResult = std::accumulate(std::next(foldContainer.begin()), foldContainer.end(), foldContainer[0],
                                           [] (const DisjunctiveInterval &l, const DisjunctiveInterval &r) {
    DisjunctiveInterval res;

    Interval e1 = l[0];
    Interval e2 = r[0];
    assert(!Interval::hasIntersection(e1,e2));
    if (e1.getUB().getSExtValue() + 1 == e2.getLB().getSExtValue()) {
      e1.join(e2);
      res.push_back(e1);
    } else {
      res.push_back(e1);
      res.push_back(e2);
    }
    return res;
  });

  return foldedResult;
}

bool DisjunctiveIntervalSummary::isDisjunctiveIntervalTop(const DisjunctiveInterval &rngs) const {
  return rngs.size() == 1 && rngs[0].IsTop();
}

DisjunctiveIntervalSummary::APIntBounds DisjunctiveIntervalSummary::getRangesForVal(const llvm::Value *V, bool &isTop) const {
  APIntBounds result;
  if (!summary.count(V)) {
    isTop = true;
    return result;
  }

  const DisjunctiveInterval &rngs = summary.at(V);
  std::transform(rngs.begin(), rngs.end(), std::back_inserter(result), [] (const Interval &r) { return r.getBounds();});

  isTop = isDisjunctiveIntervalTop(rngs);

  return result;
}

bool DisjunctiveIntervalSummary::IsTop() const {
  for (auto iter = summary.begin(); iter != summary.end(); ++iter) {
    const DisjunctiveInterval &rngs = iter->second;
    if (!isDisjunctiveIntervalTop(rngs)) {
      return false;
    }
  }
  return true;
}

std::unordered_map<const llvm::Value *, DisjunctiveIntervalSummary::APIntBounds> DisjunctiveIntervalSummary::getRangesForArgs() const {
  std::unordered_map<const llvm::Value *, DisjunctiveIntervalSummary::APIntBounds> result;

  for (auto iter = summary.begin(), eIter = summary.end(); iter != eIter; ++iter) {
    const llvm::Value* v = iter->first;
    if (!isa<Argument>(v)) continue;

    bool isTop;
    APIntBounds bounds = getRangesForVal(v, isTop);
    if (!isTop) {
      result.insert({v, bounds});
    }
  }

  return result;
}
