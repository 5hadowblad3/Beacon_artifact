#include "InstructionDbgInfo.h"
#include "llvm/IR/AssemblyAnnotationWriter.h"
#include "llvm/Support/FormattedStream.h"
#include "llvm/IR/InstIterator.h"

using namespace BackwardAI;
using namespace llvm;

InstructionDbgInfo *InstructionDbgInfo::instance = nullptr;

void InstructionDbgInfo::registerModule(const llvm::Module *M) {
  static InstructionDbgInfo dbgInfo;
  static bool hasRegistered = false;

  if (hasRegistered) {
    return;
  }

  hasRegistered = true;

  dbgInfo.buildLineInfoTable(M);
  dbgInfo.sanityCheck(M);

  instance = &dbgInfo;
}

void InstructionDbgInfo::buildLineInfoTable(const llvm::Module *M) {
  class InstructionToLineAnnotator : public llvm::AssemblyAnnotationWriter {
  public:
      void emitInstructionAnnot(const Instruction *i,
                                llvm::formatted_raw_ostream &os) {
        os << "%%%";
        os << (uintptr_t) i;
      }
  };

  InstructionToLineAnnotator a;
  std::string str;
  llvm::raw_string_ostream os(str);
  M->print(os, &a, false, true);
  os.flush();
  const char *s;

  unsigned line = 1;
  for (s=str.c_str(); *s; s++) {
    if (*s=='\n') {
      line++;
      if (s[1]=='%' && s[2]=='%' && s[3]=='%') {
        s += 4;
        char *end;
        unsigned long long value = strtoull(s, &end, 10);
        if (end!=s) {
          asmLineToInst.insert(std::make_pair(line, (const Instruction*) value));
          instToAsmLine.insert(std::make_pair((const Instruction*) value, line));
        }
        s = end;
      }
    }
  }
}

void InstructionDbgInfo::sanityCheck(const llvm::Module *M) {
  for (const auto &fun : *M) {
    for (auto iter = inst_begin(fun), eIter = inst_end(fun); iter != eIter; ++iter) {
      const Instruction *inst = &*iter;
      assert(instToAsmLine.count(inst));
    }
  }
}

unsigned InstructionDbgInfo::instToLine(const llvm::Instruction *inst) {
  return instance->instToAsmLine.at(inst);
}

const llvm::Instruction *InstructionDbgInfo::lineToInst(unsigned line) {
  return instance->asmLineToInst.at(line);
}

bool InstructionDbgInfo::hasLineInfo(const llvm::Instruction *inst) {
  return instance->instToAsmLine.count(inst);

}
