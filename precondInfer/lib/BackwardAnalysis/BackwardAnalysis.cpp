#include "klee/Expr.h"
using namespace klee;
void testB(ref<Expr> e) {
  e->dump();
}