#include "klee/SymbolicAbstractInterface.h"
using namespace absD;

RangeComputeInterface::~RangeComputeInterface() {
  freeCache();
}

void RangeComputeInterface::freeCache() {
  for (auto iter = analysisCache.begin(), eIter = analysisCache.end(); iter != eIter; ++iter) {
    RangeComputeImpl *instance = iter->second;
    delete instance;
  }
  analysisCache.clear();
}

bool RangeComputeInterface::isCondUnSat(const klee::ref<klee::Expr> &cond) {
  return analyze(cond)->isCondUnSat();
}

RangeComputeImpl * RangeComputeInterface::analyze(const klee::ref<klee::Expr> &cond) {
  if (analysisCache.size() >= 1024) {
    freeCache();
  }

  auto iter = analysisCache.find(cond);
  if (iter != analysisCache.end()) {
    return iter->second;
  } else {
    RangeComputeImpl *impl = new RangeCompute(cond);
    analysisCache.insert({cond, impl});
    return impl;
  }
}

std::pair<llvm::APInt, llvm::APInt> RangeComputeInterface::getRange(const klee::ref<klee::Expr> &cond, const klee::ref<klee::Expr> &sym) {
  return analyze(cond)->getRange(sym);
}

std::vector<std::pair<llvm::APInt, llvm::APInt>>
RangeComputeInterface::getRanges(const klee::ref<klee::Expr> &cond, const std::vector<klee::ref<klee::Expr>> &syms) {
  return analyze(cond)->getRanges(syms);
}
