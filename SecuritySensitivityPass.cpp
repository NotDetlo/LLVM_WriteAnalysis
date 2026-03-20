#include "SecuritySensitivityPass.h"

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/ADT/DenseSet.h"

using namespace llvm;

PreservedAnalyses SecuritySensitivityPass::run(Module &M, ModuleAnalysisManager &) {

    DenseSet<Value*> worklist;
    DenseSet<Function*> sensitiveFunctions;

    // =========================
    // Step 1: Find annotated globals
    // =========================
    if (GlobalVariable *annos = M.getGlobalVariable("llvm.global.annotations")) {

        if (auto *CA = dyn_cast<ConstantArray>(annos->getOperand(0))) {

            for (unsigned i = 0; i < CA->getNumOperands(); i++) {

                if (auto *CS = dyn_cast<ConstantStruct>(CA->getOperand(i))) {

                    Value *annotatedVal =
                        CS->getOperand(0)->stripPointerCasts();

                    Value *annoStrVal =
                        CS->getOperand(1)->stripPointerCasts();

                    if (auto *GV = dyn_cast<GlobalVariable>(annoStrVal)) {

                        if (auto *CDA =
                                dyn_cast<ConstantDataArray>(GV->getInitializer())) {

                            if (CDA->isString() &&
                                CDA->getAsString().contains("secret")) {

                                worklist.insert(annotatedVal);
                            }
                        }
                    }
                }
            }
        }
    }

    // =========================
    // Step 2: Data-flow + Argument propagation
    // =========================
    bool changed = true;

    while (changed) {
        changed = false;

        for (Function &F : M) {
            if (F.isDeclaration()) continue;

            for (Instruction &I : instructions(F)) {

                if (isa<DbgInfoIntrinsic>(&I)) continue;

                // LOAD
                if (auto *LI = dyn_cast<LoadInst>(&I)) {
                    if (worklist.contains(LI->getPointerOperand())) {
                        if (!worklist.contains(&I)) {
                            worklist.insert(&I);
                            changed = true;
                        }
                    }
                }

                // STORE
                if (auto *SI = dyn_cast<StoreInst>(&I)) {
                    Value *val = SI->getValueOperand();
                    Value *ptr = SI->getPointerOperand();

                    if (worklist.contains(val)) {
                        if (!worklist.contains(ptr)) {
                            worklist.insert(ptr);
                            changed = true;
                        }
                        if (!worklist.contains(&I)) {
                            worklist.insert(&I);
                            changed = true;
                        }
                    }
                }

                // 🔥 CALL ARGUMENT PROPAGATION (NEW)
                if (auto *CI = dyn_cast<CallInst>(&I)) {

                    Value *calledVal =
                        CI->getCalledOperand()->stripPointerCasts();

                    if (Function *callee = dyn_cast<Function>(calledVal)) {

                        if (!callee->isDeclaration()) {

                            for (unsigned i = 0; i < CI->arg_size(); i++) {

                                Value *arg = CI->getArgOperand(i);

                                // If argument is sensitive → propagate into callee
                                if (worklist.contains(arg)) {

                                    Argument *param = callee->getArg(i);

                                    if (!worklist.contains(param)) {
                                        worklist.insert(param);
                                        changed = true;
                                    }
                                }
                            }
                        }
                    }
                }

                // GENERAL propagation
                for (Value *op : I.operands()) {
                    if (worklist.contains(op)) {
                        if (!worklist.contains(&I)) {
                            worklist.insert(&I);
                            changed = true;
                        }
                    }
                }
            }
        }
    }

    // =========================
    // Step 3: Mark functions
    // =========================
    for (Function &F : M) {
        if (F.isDeclaration()) continue;

        for (Instruction &I : instructions(F)) {
            if (worklist.contains(&I)) {
                sensitiveFunctions.insert(&F);
                break;
            }
        }
    }

    // =========================
    // Step 4: Output
    // =========================
    for (Function &F : M) {
        if (F.isDeclaration()) continue;

        double sensitivityScore =
            sensitiveFunctions.contains(&F) ? 1.0 : 0.0;

        errs() << "----------------------------------\n";
        errs() << "Function: " << F.getName() << "\n";
        errs() << "Sensitivity: " << sensitivityScore << "\n";
    }

    return PreservedAnalyses::all();
}