#ifndef ABSD_SYMBOLIC_ABSTRACT_INTERFACE_H
#define ABSD_SYMBOLIC_ABSTRACT_INTERFACE_H
#include "klee/Expr.h"
#include "klee/util/ExprHashMap.h"
namespace absD {
    class RangeComputeImpl {
    public:
      virtual std::pair<llvm::APInt, llvm::APInt> getRange(const klee::ref<klee::Expr> &sym) = 0;
      virtual bool isCondUnSat() = 0;
      virtual std::vector<std::pair<llvm::APInt, llvm::APInt>> getRanges(const std::vector<klee::ref<klee::Expr>> &syms) = 0;
      virtual ~RangeComputeImpl() {}
    };

    class RangeAnalysis;
    class RangeCompute: public RangeComputeImpl {
    public:
        RangeCompute(const klee::ref<klee::Expr> &cond);

        bool isCondUnSat() override;
        std::pair<llvm::APInt, llvm::APInt> getRange(const klee::ref<klee::Expr> &sym) override;

        std::vector<std::pair<llvm::APInt, llvm::APInt>>
        getRanges(const std::vector<klee::ref<klee::Expr>> &syms) override;

        ~RangeCompute();
    private:
        RangeAnalysis* impl = nullptr;
        bool isUnsat = false;
    };

    class RangeComputeInterface {
    public:
      RangeComputeInterface () {}
      ~RangeComputeInterface();

      bool isCondUnSat(const klee::ref<klee::Expr> &cond);

      std::pair<llvm::APInt, llvm::APInt> getRange(const klee::ref<klee::Expr> &cond, const klee::ref<klee::Expr> &sym);

      std::vector<std::pair<llvm::APInt, llvm::APInt>>
        getRanges(const klee::ref<klee::Expr> &cond, const std::vector<klee::ref<klee::Expr>> &syms);
    private:
      RangeComputeImpl * analyze(const klee::ref<klee::Expr> &cond);

      klee::ExprHashMap<RangeComputeImpl *> analysisCache;
      void freeCache();

    };
}
#endif
