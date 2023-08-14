#include "WPCondition.h"
#include "InstructionDbgInfo.h"
#include "klee/WPInferenceInterface.h"
#include "klee/Internal/System/Time.h"
#include "klee/Internal/System/MemoryUsage.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Bitcode/BitcodeWriter.h"

#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/prettywriter.h"
#include <fstream>
#include <numeric>
#include <functional>
#include <iterator>

using namespace BackwardAI;
using namespace llvm;

extern cl::opt<bool> ReachBBOnly;
extern cl::opt<std::string> TargetFile;
extern cl::opt<bool> DebugSwitch;

namespace {
  ICFG *icfg = nullptr;

  std::string llvmValToStr(const Value *V) {
    std::string str;
    llvm::raw_string_ostream os(str);
    os << *V;

    return os.str();

    /*if (V->getName().str() != "") {
      return V->getName().str();
    } else {
      const void * address = static_cast<const void*>(V);
      std::stringstream ss;
      ss << address;
      std::string addr = ss.str();
      return "tmp_" + addr;
    }*/

  }

  std::string llvmFunToStr(const Function *fun) {
    const void * address = static_cast<const void*>(fun);
    std::stringstream ss;
    ss << address;
    std::string addr = ss.str();

    std::string funName = fun->getName().str() + "_" + addr;
    return funName;
  }

  std::string disjointRangeSetToStr(const std::vector<std::pair<llvm::APInt, llvm::APInt>> &s) {
    auto rngToStr = [] (std::pair<llvm::APInt, llvm::APInt> rng) -> std::string {
//      auto lb = rng.first.getZExtValue();
//      auto ub = rng.second.getZExtValue();

      auto slb = rng.first.getSExtValue();
      auto sub = rng.second.getSExtValue();

      std::stringstream ss;
//      ss << "[" << lb << "(" << slb << ")"<< "," << ub << "(" << sub << ")"<< "]";
      ss << "[" << slb << "," << sub << "]";
      return ss.str();
    };

    std::vector<std::string> rangeStrs;
    std::transform(s.begin(), s.end(), std::back_inserter(rangeStrs), rngToStr);

    auto res = std::accumulate(std::next(rangeStrs.begin()), rangeStrs.end(),
                                   rangeStrs[0], [](std::string s1, std::string s2) {
      return s1 + "∪" + s2;
    });

    return res;
  }

}

namespace {
 klee::time::Point BeginTime;
 klee::time::Span PointerTime;
 klee::time::Span TotalTime;
}

std::unordered_map<const llvm::Function*, WPInferenceInterface::FunctionResult> WPInferenceInterface::getResult() {
  return analysisResultByFun;
}

WPInferenceInterface::WPInferenceInterface(Module *M, std::set<const llvm::Instruction*> targets, bool isInterProc)
  : M(M), targets(std::move(targets)), isInterAnalysis(isInterProc) {
  BeginTime = klee::time::getWallTime();
  icfg = new ICFG(M, true);
  PointerTime = klee::time::getWallTime() - BeginTime;

  /// The pointer analysis will modify M
  InstructionDbgInfo::registerModule(M);

  if (ReachBBOnly) {
    return;
  }

  llvm::errs() << "Assembly of bitcode written to debugIR.ll...\n";
  std::error_code EC;
  llvm::raw_fd_ostream oss("debugIR.ll", EC, sys::fs::F_None);
  M->print(oss, nullptr, false, true); /// same as dump
  oss.flush();

  llvm::errs() << "transformed bc written to transed.bc...\n";
  llvm::raw_fd_ostream oss2("transed.bc", EC, sys::fs::F_None);
  WriteBitcodeToFile(M, oss2);
}

unsigned WPInferenceInterface::getAsmLineAtInst(const llvm::Instruction *inst) const {
  return InstructionDbgInfo::instToLine(inst);
}

WPInferenceInterface::~WPInferenceInterface() {
  delete icfg;
}

void WPInferenceInterface::run(bool useSolver) {
  assert(targets.size() == 1 && "multi targets not supported yet!\n");
  for (auto target : targets) {
    runForTarget(target, useSolver);
  }
}


namespace {
    void getDebugLoc(const Instruction *I, std::string &Filename,
                            unsigned &Line) {

      if(I == nullptr || !I->hasMetadata()) {
        return;
      }

      DILocation *Loc = I->getDebugLoc();

      if (Loc) {
        Line = Loc->getLine();
        Filename = Loc->getFilename().str();

        if (Filename.empty()) {
          DILocation *oDILoc = Loc->getInlinedAt();
          if (oDILoc) {
            Line = oDILoc->getLine();
            Filename = oDILoc->getFilename().str();
          }
        }
      }

    }
}



void WPInferenceInterface::dumpReachBBs(const std::set<const llvm::BasicBlock*> &targetBBs) {
  assert(targets.size() == 1 && "multi targets not supported yet!\n");
  std::unordered_set<const llvm::BasicBlock*> reachBBs;

  if (DebugSwitch) {
    llvm::errs() << "Number of target bbs " << targetBBs.size() << "\n";
  }

  /// a single source location can corresponds to multiple bbs.
  for (auto bb : targetBBs) {
    auto inst = bb->getTerminator();
    assert(inst);

    auto bbs = icfg->getReachable(inst);
    reachBBs.insert(bbs.begin(), bbs.end());
  }

  std::error_code EC;
  llvm::raw_fd_ostream oss("bbreaches.txt", EC, sys::fs::F_None);

  for (auto bb : reachBBs) {
    auto inst = &*bb->begin();
    unsigned asmLine = InstructionDbgInfo::instToLine(inst);
    oss << asmLine << "\n";

    /*if (bb->getParent()->getName().str() == "main") {
      std::string bbName;
      llvm::raw_string_ostream os(bbName);
      bb->printAsOperand(os, false);
      llvm::errs() << "main:" << os.str() << "\n";
    }

    for (auto &inst : *bb) {
      std::string filename;
      unsigned line;

      getDebugLoc(&inst, filename, line);

      if (filename.empty() || line == 0) {
        continue;
      }

      std::size_t found = filename.find_last_of("/\\");
      if (found != std::string::npos)
        filename = filename.substr(found + 1);

      auto loc = std::to_string(line);
      auto bb_name = filename + ":" + loc;

      oss << bb_name << "\n";
      break;

    }*/

  }


}

void WPInferenceInterface::runForTarget(const Instruction *target, bool useSolver) {
  llvm::errs() << "Starting fixpoint computation for " << target->getFunction()->getName() << "\n";

  auto fromFixpoResult = [] (const PreconditionFixpo::FixpointDisjunctiveResult &fixpoRes) {
      return FunctionResult(fixpoRes.getArgResult(), fixpoRes.getValResult(), fixpoRes.getConditionedBBs(), fixpoRes.getUnreachableBBs());
  };

  PreconditionFixpo fixpo(target, *icfg, isInterAnalysis);
  fixpo.init();
  fixpo.run();

  std::unordered_map<const llvm::Function*, PreconditionFixpo::FixpointDisjunctiveResult> analysisRes = fixpo.getAnalysisResult();
  unsigned condbbCnt = 0, unreachbbCnt = 0;
  for (const auto &funRes : analysisRes) {
    auto fun = funRes.first;
    const PreconditionFixpo::FixpointDisjunctiveResult &fixpoResult = funRes.second;
    analysisResultByFun.insert({fun, fromFixpoResult(fixpoResult)});

    condbbCnt += fixpoResult.getConditionedBBs().size();
    unreachbbCnt += fixpoResult.getUnreachableBBs().size();
  }

  llvm::errs() << "Finish fixpoint computation for " << target->getFunction()->getName() << "\n";
  llvm::errs() << "Discover conditional reachable bbs: " << condbbCnt << "\n";
  llvm::errs() << "Discover unreachable bbs: " << unreachbbCnt << "\n";
}

void WPInferenceInterface::dumpTime() {
  TotalTime = klee::time::getWallTime() - BeginTime;

  auto ptrHMS = PointerTime.toHMS();
  std::uint32_t ptrH = std::get<0>(ptrHMS);
  std::uint8_t ptrM = std::get<1>(ptrHMS);
  std::uint8_t ptrS = std::get<2>(ptrHMS);

  auto totHMS = TotalTime.toHMS();
  std::uint32_t totH = std::get<0>(totHMS);
  std::uint8_t totM = std::get<1>(totHMS);
  std::uint8_t totS = std::get<2>(totHMS);

  std::ofstream oss("time.info");
  if (oss.is_open()) {
    oss << "Pointer time: " << ptrH << "h:" << (uint32_t) ptrM << "m:" << (uint32_t) ptrS << "s\n";
    oss << "Total time: " << totH << "h:" << (uint32_t) totM << "m:" << (uint32_t) totS << "s\n";
    oss.close();
  } else {
    llvm::errs() << "Unable to open time.info\n";
  }
}

void WPInferenceInterface::dumpMem() {
  unsigned mbs = (klee::util::GetTotalMallocUsage() >> 20);
  std::ofstream oss("mem.info");
  if (oss.is_open()) {
    oss << "memory: " << mbs << "mbs\n";
    oss.close();
  } else {
    llvm::errs() << "Unable to open mem.info\n";
  }
}

void WPInferenceInterface::dumpResult() {
  rapidjson::Document dom;
  dom.SetArray();
  auto &allocator = dom.GetAllocator();

  for (auto iter = analysisResultByFun.begin(); iter != analysisResultByFun.end(); ++iter) {
    const FunctionResult &funRes = iter->second;
    if (funRes.valResult.empty() && funRes.argResult.empty() && funRes.unreachableBBs.empty()) {
      continue;
    }

    rapidjson::Value funRecord(rapidjson::kObjectType);

    const Function *fun = iter->first;
    const llvm::Instruction *firstInstOfFunc = &*fun->begin()->begin();
    std::string funName = llvmFunToStr(iter->first);

    rapidjson::Value funNameV; funNameV.SetString(funName.c_str(), funName.size(), allocator);
    rapidjson::Value funLocV; funLocV.SetUint(getAsmLineAtInst(firstInstOfFunc));
    funRecord.AddMember("fun", funNameV, allocator);
    funRecord.AddMember("funLoc", funLocV, allocator);


    rapidjson::Value instResultArr(rapidjson::kArrayType);
    for (const auto &instRng : funRes.valResult) {
      std::string instName = llvmValToStr(instRng.first);
      std::string rangeRes = disjointRangeSetToStr(instRng.second);

//      llvm::errs() << instName << "\n";
//      llvm::errs() << rangeRes << "\n";

      rapidjson::Value instResult(rapidjson::kObjectType);
      rapidjson::Value instNameV; instNameV.SetString(instName.c_str(), instName.size(), allocator);
      rapidjson::Value rangeV; rangeV.SetString(rangeRes.c_str(), rangeRes.size(), allocator);
      rapidjson::Value lineV; lineV.SetUint(getAsmLineAtInst(instRng.first));

      instResult.AddMember("value", instNameV, allocator);
      instResult.AddMember("range", rangeV, allocator);
      instResult.AddMember("line", lineV, allocator);
      instResultArr.PushBack(instResult, allocator);
    }

    funRecord.AddMember("instRes", instResultArr, allocator);
    rapidjson::Value argResultArr(rapidjson::kArrayType);

    for (const auto &argRng : funRes.argResult) {
      rapidjson::Value argResult(rapidjson::kObjectType);
      const Argument *argVal = cast<Argument>(argRng.first);
      assert(argVal->getParent() == fun);
      auto loc = &*fun->begin()->begin();
      rapidjson::Value lineV; lineV.SetUint(getAsmLineAtInst(loc));
      rapidjson::Value argNoV; argNoV.SetUint(argVal->getArgNo());

      std::string rangeRes = disjointRangeSetToStr(argRng.second);
      rapidjson::Value rngV; rngV.SetString(rangeRes.c_str(), rangeRes.size(), allocator);

      argResult.AddMember("argNO", argNoV, allocator);
      argResult.AddMember("range", rngV, allocator);
      argResult.AddMember("location", lineV, allocator);

      argResultArr.PushBack(argResult, allocator);
    }

    funRecord.AddMember("argRes", argResultArr, allocator);

    rapidjson::Value unreachBBArr(rapidjson::kArrayType);
    for (auto bb : funRes.unreachableBBs) {
      rapidjson::Value locV; locV.SetUint(getAsmLineAtInst(&*bb->begin()));
      unreachBBArr.PushBack(locV, allocator);
    }

    funRecord.AddMember("unreachbb", unreachBBArr, allocator);

    dom.PushBack(funRecord, allocator);
  }

  rapidjson::StringBuffer sb;
  rapidjson::PrettyWriter<rapidjson::StringBuffer> writer(sb);
  dom.Accept(writer);    // Accept() traverses the DOM and generates Handler events.
  const char* json = sb.GetString();

  FILE *fp = fopen( "range_res.txt" , "w" );
  fwrite(json, 1 , sb.GetLength(), fp );
  fclose(fp);

  dumpTime();
  dumpMem();
}

static std::vector<std::pair<llvm::APInt, llvm::APInt>> strToRange(std::string s, unsigned w) {
  /// [1,2]∪[4,5] ..
  std::vector<std::pair<llvm::APInt, llvm::APInt>> res;

  auto addIntervalToRes = [&res, w] (std::string itvS) {
    std::istringstream iss(itvS);
    char leftBracket, comma, rightBracket;
    int64_t lb, ub;

    auto &stream = iss >> leftBracket >> lb >> comma >> ub >> rightBracket;
    assert(stream.good());

    APInt aplb(w, lb);
    APInt apub(w, ub);
    res.push_back({aplb, apub});
  };

  size_t pos = 0;
  std::string itvS;
  std::string delimiter = "∪";

  while ((pos = s.find(delimiter)) != std::string::npos) {
    itvS = s.substr(0, pos);
    addIntervalToRes(itvS);
    s.erase(0, pos + delimiter.length());
  }

  assert(!s.empty());
  addIntervalToRes(s);

  return res;
}

std::unordered_map<const llvm::Function*, WPInferenceInterface::FunctionResult>
PersistenceAnalysisData::deserialize(const llvm::Module *M, const std::string &resultJson) {
  std::unordered_map<const llvm::Function*, WPInferenceInterface::FunctionResult> res;

  InstructionDbgInfo::registerModule(M);
  std::ifstream ifs(resultJson);
  std::string content((std::istreambuf_iterator<char>(ifs)),
                       (std::istreambuf_iterator<char>()));

  rapidjson::Document dom;
  dom.Parse(content.c_str());
  for (auto& funRecord : dom.GetArray()) {
    assert(funRecord.HasMember("funLoc"));
    unsigned funLoc = funRecord["funLoc"].GetUint();
    const Instruction * firstInstOfFunc = InstructionDbgInfo::lineToInst(funLoc);
    const Function *funKey = firstInstOfFunc->getFunction();
    std::unordered_map<const llvm::Value*, std::vector<std::pair<llvm::APInt, llvm::APInt>>> argResult;
    std::unordered_map<const llvm::Instruction*, std::vector<std::pair<llvm::APInt, llvm::APInt>>> valResult;
    std::set<const llvm::BasicBlock *> unreachableBBs;

    assert(funRecord.HasMember("instRes"));
    for (auto &instRes : funRecord["instRes"].GetArray()) {
      unsigned instLoc = instRes["line"].GetUint();
      std::string rangeStr = instRes["range"].GetString();

      const Instruction *llvmInst = InstructionDbgInfo::lineToInst(instLoc);
      unsigned width = llvmInst->getType()->getIntegerBitWidth();
      auto ranges = strToRange(rangeStr, width);

      assert(valResult.insert({llvmInst, ranges}).second);
    }

    assert(funRecord.HasMember("argRes"));
    for (auto &argRes : funRecord["argRes"].GetArray()) {
      unsigned argNo = argRes["argNO"].GetUint();
      std::string rangeStr = argRes["range"].GetString();

      unsigned idx = 0;
      const Argument *arg = nullptr;
      for (auto argIter = funKey->arg_begin(), eIter = funKey->arg_end(); argIter != eIter; ++argIter) {
        if (idx == argNo) {
          arg = &*argIter;
          break;
        }
        ++idx;
      }

      assert(arg);
      auto ranges = strToRange(rangeStr, arg->getType()->getIntegerBitWidth());
      assert(argResult.insert({arg, ranges}).second);
    }

    assert(funRecord.HasMember("unreachbb"));
    for (auto &unreachbb : funRecord["unreachbb"].GetArray()) {
      unsigned bbLoc = unreachbb.GetUint();
      const Instruction *llvmInst = InstructionDbgInfo::lineToInst(bbLoc);
      unreachableBBs.insert(llvmInst->getParent());
    }

    WPInferenceInterface::FunctionResult funResult(argResult, valResult, {}, unreachableBBs);
    if (argResult.empty() && valResult.empty() && unreachableBBs.empty()) {

    } else {
      assert(res.insert({funKey, funResult}).second);
    }
  }

  return res;
}
