#ifndef ABSTRACT_STATE_H
#define ABSTRACT_STATE_H

#include "klee/Expr.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/ADT/APInt.h"
#include <unordered_map>
namespace BackwardAI {
  class Interval {
  public:
    Interval(std::pair<llvm::APInt, llvm::APInt> bounds, bool isSigned);
    Interval(const Interval &rhs);
    Interval& operator=(const Interval &rhs);

    static Interval createBottom(unsigned w, bool isSigned);
    static Interval createTop(unsigned w, bool isSigned);

    bool IsTop() const {
      unsigned w = getLB().getBitWidth();
      return getLB() == getMinVal(w, isSigned) && getUB() == getMaxVal(w, isSigned);
    }

    bool IsBot() const {
      return range_gt(getLB(), getUB(), isSigned);
    }

    llvm::APInt getLB() const {
      return bounds.first;
    }

    llvm::APInt getUB() const {
      return bounds.second;
    }

    std::pair<llvm::APInt, llvm::APInt> getBounds() const {
      return bounds;
    }

    void join(const Interval &rhs);
    void meet(const Interval &rhs);
    static bool hasIntersection(Interval lhs, Interval rhs);
    void widen(const Interval &rhs);
    bool isLessOrEqual(const Interval &rhs) const;
    std::string toStr() const;

    unsigned getWidth() const {
      return bounds.first.getBitWidth();
    }

    void setLB(llvm::APInt v) {
      bounds.first = v;
    }

    void setUB(llvm::APInt v) {
      bounds.second = v;
    }

  private:
    const bool isSigned;
    std::pair<llvm::APInt, llvm::APInt> bounds;

    void assignRhs(const Interval &rhs) {
      bounds = rhs.bounds;
    }

    void sanityCheck(const Interval &rhs) const {
      assert(isSigned == rhs.isSigned);
      assert(getWidth() == rhs.getWidth());
    }

    void normalize();
  public:
    static bool range_le(const llvm::APInt &lhs, const llvm::APInt &rhs, bool isSigned);
    static bool range_lt(const llvm::APInt &lhs, const llvm::APInt &rhs, bool isSigned);
    static bool range_ge(const llvm::APInt &lhs, const llvm::APInt &rhs, bool isSigned);
    static bool range_gt(const llvm::APInt &lhs, const llvm::APInt &rhs, bool isSigned);
    static llvm::APInt getMinVal(unsigned w, bool isSigned);
    static llvm::APInt getMaxVal(unsigned w, bool isSigned);

  };

  class AbstractState {
  public:
    struct MemKeyHasher {
        std::size_t operator()(const std::pair<const llvm::Value*, unsigned>& k) const
        {
          return std::hash<const llvm::Value *>()(k.first) ^ std::hash<unsigned > () (k.second);
        }
    };

  private:
    const std::set<const llvm::Value*> &valKeys;
    const std::set<std::pair<const llvm::Value*, unsigned>> &memKeys;
    std::unordered_map<const llvm::Value*, Interval> valRng;
    std::unordered_map<std::pair<const llvm::Value*, unsigned>, Interval, MemKeyHasher> memRng;
    void assignRhs(const AbstractState &rhs);
  public:
    /// At construction, is bottom value
    AbstractState(decltype(valKeys) valKeys, decltype(memKeys) memKeys) : valKeys(valKeys), memKeys(memKeys) {}
    void set(decltype(valRng) valRng, decltype(memRng) memRng);

    const std::set<const llvm::Value*> &getValKeys() const {
      return valKeys;
    }

    const std::set<std::pair<const llvm::Value*, unsigned>> & getMemKeys() const {
      return memKeys;
    }

    Interval getRangeForValue(const llvm::Value *v) const;
    Interval getRangeForMem(std::pair<const llvm::Value*, unsigned>) const;

    Interval accessRangeForValue (const llvm::Value *v) const {
      return valRng.at(v);
    }

    bool IsBot() const;
    bool IsTop() const;
    void join(const AbstractState &rhs);
    void widen(const AbstractState &rhs);
    bool isLessOrEqual(const AbstractState &rhs) const;

    std::unordered_map<const llvm::Value*, Interval>::iterator val_begin() {
      return valRng.begin();
    }

    std::unordered_map<const llvm::Value*, Interval>::iterator val_end() {
      return valRng.end();
    }

    decltype(memRng)::iterator mem_begin() {
      return memRng.begin();
    }

    decltype(memRng)::iterator mem_end() {
      return memRng.end();
    }
  };

  class DisjunctiveIntervalSummary {
  public:
    DisjunctiveIntervalSummary(const std::vector<std::shared_ptr<AbstractState>>);
    using APIntBounds = std::vector<std::pair<llvm::APInt, llvm::APInt>>;
    APIntBounds getRangesForVal(const llvm::Value*, bool &isTop) const;
    std::unordered_map<const llvm::Value *, APIntBounds> getRangesForArgs() const;
    bool IsTop() const;
  private:
    using DisjunctiveInterval = std::vector<Interval>;
    std::unordered_map<const llvm::Value*, DisjunctiveInterval> summary;

    DisjunctiveInterval addToDisjointIntervals(const DisjunctiveInterval &s, Interval itv);
    bool isDisjunctiveIntervalTop(const DisjunctiveInterval &itv) const;
  };

}




#endif