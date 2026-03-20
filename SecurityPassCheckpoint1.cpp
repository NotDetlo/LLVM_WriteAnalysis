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

    errs() << "Security pass is running\n"; // ✅ debug

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
    // Step 2: Propagation
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
                        worklist.insert(&I);
                        changed = true;
                    }
                }

                // STORE
                if (auto *SI = dyn_cast<StoreInst>(&I)) {
                    Value *val = SI->getValueOperand();
                    Value *ptr = SI->getPointerOperand();

                    if (worklist.contains(val)) {
                        worklist.insert(ptr);
                        worklist.insert(&I);
                        changed = true;
                    }
                }

                // 🔥 CALL ARGUMENT PROPAGATION
                if (auto *CI = dyn_cast<CallInst>(&I)) {

                    Value *calledVal =
                        CI->getCalledOperand()->stripPointerCasts();

                    if (Function *callee = dyn_cast<Function>(calledVal)) {

                        if (!callee->isDeclaration()) {

                            for (unsigned i = 0; i < CI->arg_size(); i++) {

                                Value *arg = CI->getArgOperand(i);

                                if (worklist.contains(arg)) {

                                    Argument *param = callee->getArg(i);

                                    worklist.insert(param);
                                    changed = true;
                                }
                            }
                        }
                    }

                    // 🔥 ALSO mark call if argument is sensitive
                    for (Value *arg : CI->args()) {
                        if (worklist.contains(arg)) {
                            worklist.insert(&I);
                            changed = true;
                            break;
                        }
                    }
                }

                // 🔥 RETURN propagation (NEW, important)
                if (auto *RI = dyn_cast<ReturnInst>(&I)) {

                    Value *retVal = RI->getReturnValue();

                    if (retVal && worklist.contains(retVal)) {

                        Function *currFunc = I.getFunction();

                        for (User *U : currFunc->users()) {
                            if (auto *call = dyn_cast<CallInst>(U)) {
                                worklist.insert(call);
                                changed = true;
                            }
                        }
                    }
                }

                // GENERAL propagation
                for (Value *op : I.operands()) {
                    if (worklist.contains(op)) {
                        worklist.insert(&I);
                        changed = true;
                        break;
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
    errs() << "\n===== Security Analysis Results =====\n";

    for (Function &F : M) {
        if (F.isDeclaration()) continue;

        errs() << "Function: " << F.getName()
               << (sensitiveFunctions.contains(&F)
                       ? " → SENSITIVE\n"
                       : " → NOT SENSITIVE\n");
    }

    return PreservedAnalyses::all();
}