#ifndef _DESERIALIZE_H_
#define _DESERIALIZE_H_

#include "llvm/IR/Module.h"
#include "llvm/IR/Instruction.h"
#include "llvm/ADT/APInt.h"
#include <vector>
#include <set>
#include <unordered_map>

struct FunctionResult {
    std::unordered_map<const llvm::Value*, std::vector<std::pair<llvm::APInt, llvm::APInt>>> argResult;
    std::unordered_map<const llvm::Instruction*, std::vector<std::pair<llvm::APInt, llvm::APInt>>> valResult;
    std::set<const llvm::BasicBlock *> conditionedBBs;
    std::set<const llvm::BasicBlock *> unreachableBBs;

    FunctionResult(decltype(argResult) argRes, decltype(valResult) valRes,
                   decltype(conditionedBBs) condbbs, decltype(unreachableBBs) unreachbbs) :
                   argResult(std::move(argRes)), valResult(std::move(valRes)), conditionedBBs(std::move(condbbs)), unreachableBBs(std::move(unreachbbs)) {}

                   FunctionResult() {}
};

class PersistenceAnalysisData {
public:
    static std::unordered_map<const llvm::Function*, FunctionResult>
    deserialize(const llvm::Module *, const std::string &resultJson);
    static std::set<const llvm::BasicBlock*> getReachableBBs(const llvm::Module *M, const std::string &fname);
};

#endif


