#include "SecurityState.h"

namespace SecurityState {
    llvm::DenseSet<const llvm::Value*> SensitiveValues;
}