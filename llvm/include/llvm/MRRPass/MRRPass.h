/**
 * @brief transform memory operation to getter or setter
 * @file MRRPass.h
 */

#ifndef MRR_MRRPASS_H
#define MRR_MRRPASS_H

#include <set>
#include <vector>

#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Pass.h"

#include "llvm/ADT/Statistic.h"
#include "llvm/IR/Constant.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/DerivedTypes.h"

#include "llvm/Analysis/PostDominators.h"

#include "llvm/Transforms/IPO/PassManagerBuilder.h"

#include "llvm/Support/raw_ostream.h"

using namespace llvm;
namespace llvm {
    namespace MRR {
        Pass *createMrrPass();
    }

}


class MemOpTransformation {
public:
    MemOpTransformation(Function &F);
    // Analysis phase
    bool isFuncTransformed();
    bool isFunctionToSkip();
    bool isRootFunction();
    void collectGlobalVars();
    bool isInstLoadGvars(LoadInst *load);
    bool isInstStoreGvars(StoreInst *store);
    void collectInstsUseGlobal();
    void collectRetInsts();
    void collectKernelMemCallee();
    // transformation phase
    void performTransformation();
    void insertGvarRecordInst();
    void insertRstoreFunc();
    void replaceLoadGvarByGetter();
    void replaceStoreGvarBySetter();
    void insertMemMonitor();

private:
    std::set<GlobalVariable *> globalVarSet;
    std::set<Instruction *> instLoadGvars;
    std::set<Instruction *> instStoreGvars;
    std::set<Instruction *> retInsts;
    std::set<Instruction *> memAllocCallees;
    std::set<Instruction *> memFreeCallees;
    Module *parentModule;
    Function *funcToModified;
    bool isTransformed = false;
    bool isSkiped = false;
    bool isRootFunc = false;

};

#endif
