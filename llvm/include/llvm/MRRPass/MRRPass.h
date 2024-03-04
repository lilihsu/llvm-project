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
    bool isModuleTransformed();

};

#endif
