// MemRecord
#include "llvm/MRRPass/MRRPass.h"


using namespace llvm;
using namespace MRR;

MemOpTransformation::MemOpTransformation(Function &F) {
    errs() <<F.getName() << "\n";
    
}

bool MemOpTransformation::isModuleTransformed() {
    return false;
}

namespace {
    struct MRRPass : public FunctionPass {
        static char ID;
        MRRPass() : FunctionPass(ID) {}

        bool runOnFunction(Function &F) override {
            MemOpTransformation transformation(F);
            errs() << getPassName() << "\n";
            errs() << "fuck you" << "\n";
            return transformation.isModuleTransformed();
        } 
    };

}
Pass *llvm::MRR::createMrrPass() {
    return new MRRPass();
}


char MRRPass::ID = 0;
