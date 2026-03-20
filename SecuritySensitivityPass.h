#pragma once

#include "llvm/IR/PassManager.h"

using namespace llvm;

class SecuritySensitivityPass : public PassInfoMixin<SecuritySensitivityPass> {
public:
    PreservedAnalyses run(Module &M, ModuleAnalysisManager &);
};