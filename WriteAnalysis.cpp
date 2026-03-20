#include "llvm/IR/PassManager.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Support/raw_ostream.h"

#include "SecuritySensitivityPass.h"

using namespace llvm;

namespace {

class MemoryBehaviorPass : public PassInfoMixin<MemoryBehaviorPass> {

public:
    static bool isRequired() { return true; }

    PreservedAnalyses run(Function &F, FunctionAnalysisManager &) {

        int storeCount = 0;
        int loadCount = 0;
        int instructionCount = 0;

        for (BasicBlock &BB : F) {
            for (Instruction &I : BB) {

                instructionCount++;

                if (isa<StoreInst>(&I)) storeCount++;
                if (isa<LoadInst>(&I)) loadCount++;
            }
        }

        double writeFrequency = 0.0;
        double memoryIntensity = 0.0;

        if (instructionCount > 0) {
            writeFrequency = (double)storeCount / instructionCount;
            memoryIntensity = (double)(storeCount + loadCount) / instructionCount;
        }

        errs() << "----------------------------------\n";
        errs() << "Function: " << F.getName() << "\n";
        errs() << "Instruction Count: " << instructionCount << "\n";
        errs() << "Store Count: " << storeCount << "\n";
        errs() << "Load Count: " << loadCount << "\n";
        errs() << "Write Frequency: " << writeFrequency << "\n";
        errs() << "Memory Intensity: " << memoryIntensity << "\n";

        return PreservedAnalyses::all();
    }
};

} // namespace

extern "C" LLVM_ATTRIBUTE_WEAK PassPluginLibraryInfo llvmGetPassPluginInfo() {

    return {
        LLVM_PLUGIN_API_VERSION,
        "LLVMAnalysisPass",
        LLVM_VERSION_STRING,
        [](PassBuilder &PB) {

            // ✅ Function pass registration
            PB.registerPipelineParsingCallback(
                [](StringRef Name,
                   FunctionPassManager &FPM,
                   ArrayRef<PassBuilder::PipelineElement>) {

                    if (Name == "memory-behavior") {
                        FPM.addPass(MemoryBehaviorPass());
                        return true;
                    }

                    return false;
                });

            // ✅ Module pass registration (FIXED)
            PB.registerPipelineParsingCallback(
                [](StringRef Name,
                   ModulePassManager &MPM,
                   ArrayRef<PassBuilder::PipelineElement>) {

                    if (Name == "security-sensitivity") {
                        MPM.addPass(SecuritySensitivityPass());
                        return true;
                    }

                    return false;
                });
        }
    };
}