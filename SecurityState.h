#pragma once
#include "llvm/IR/Value.h"
#include "llvm/ADT/DenseSet.h"

namespace SecurityState {
    extern llvm::DenseSet<const llvm::Value*> SensitiveValues;
}