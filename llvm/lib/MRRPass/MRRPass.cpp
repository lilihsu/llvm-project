// MemRecord
#include "llvm/MRRPass/MRRPass.h"


using namespace llvm;
using namespace MRR;

const StringRef syscall_root = "kvm_uevent_notify_change";

const std::set<StringRef> funcs_to_instrument = {
    syscall_root,
};

const std::set<StringRef> kernel_allocation_funcs = {
    "kmalloc",
    "kzalloc",
    "neigh_parms_alloc",
    "nlmsg_new",
    "kmemdup",
    "alloc_percpu",
    "__alloc_percpu",
    "alloc_percpu_gfp",
    "__alloc_percpu_gfp",
    "kmalloc_array",
    "kcalloc",
    "genlmsg_new",
    "sk_alloc",
    "kmem_cache_zalloc",
    "nla_memdup",
    "kzalloc_node",
    "fib_rules_register",
};

const std::set<StringRef> kernel_free_funcs = {
    "kfree",
    "kvfree",
};

const std::set<StringRef> global_vars = {
    "kvm_createvm_count",
    "kvm_active_vms",
};
// monitor api

const StringRef turn_on_compart_flag = "turn_on_compart_flag";
const StringRef turn_off_compart_flag = "turn_off_compart_flag";
const StringRef recover = "recover";
const StringRef restore = "restore";
const StringRef new_global_data = "new_global_data";
const StringRef set_global_data = "set_global_data";

MemOpTransformation::MemOpTransformation(Function &F) {
    if (funcs_to_instrument.find(F.getName()) == funcs_to_instrument.end()) {
        isSkiped = true;
        // errs() << "[skipped function name]:" << F.getName() << "\n";
        return;
    }

    parentModule = F.getParent(); 
    funcToModified = &F;

    if (F.getName() == syscall_root) {
        isRootFunc = true;
        errs() << "[Find root function]:" << F.getName() << "\n";
        collectGlobalVars();
    }
    errs() <<F.getName() << "\n";
}

bool MemOpTransformation::isFuncTransformed() {
    return isTransformed;
}

bool MemOpTransformation::isFunctionToSkip() {
    return isSkiped;
}

bool MemOpTransformation::isRootFunction() {
    return isRootFunc;
}

void MemOpTransformation::collectGlobalVars() {
    std::set<StringRef>::iterator it;
    for (it = global_vars.begin(); it != global_vars.end(); ++it) {
        GlobalVariable *tmp;
        tmp = parentModule->getNamedGlobal(*it);
        if (tmp == NULL) {
            continue;
        }
        errs() << "[collected global variable]:" << tmp->getName() <<"\n";
        globalVarSet.insert(tmp);
    }
}

bool MemOpTransformation::isInstLoadGvars(LoadInst *load) {
    if (GlobalVariable * gvar = dyn_cast<GlobalVariable>(load->getPointerOperand())) {
        if (globalVarSet.find(gvar) != globalVarSet.end()) {
            return true;
        }
    }

    return false;
}

bool MemOpTransformation::isInstStoreGvars(StoreInst *store) {
    if (GlobalVariable * gvar = dyn_cast<GlobalVariable>(store->getPointerOperand())) {
        if (globalVarSet.find(gvar) != globalVarSet.end()) {
            return true;
        }
    }
    
    return false;
}

void MemOpTransformation::collectInstsUseGlobal() {
    for (auto it = inst_begin(funcToModified); it != inst_end(funcToModified); ++it) {
        Instruction *inst = &*it;

        if (LoadInst *load = dyn_cast<LoadInst> (inst)) {
            if (isInstLoadGvars(load))
                instLoadGvars.insert(load);
        } else if (StoreInst *store = dyn_cast<StoreInst>(inst)) {
            if (isInstStoreGvars(store))
                instStoreGvars.insert(store);
        }
    }
 
}

void MemOpTransformation::performTransformation() {
    if (isRootFunction()) {
        insertGvarRecordInst();
        insertRstoreFunc();
    }
}

void MemOpTransformation::insertGvarRecordInst() {
    errs() << "[Perform insertGvarRecordInst]" << "\n";
    BasicBlock *bb = &(funcToModified->getEntryBlock());
    Instruction *i = bb->getFirstNonPHI();
    
    IRBuilder<> irBuilder(i);
    std::set<GlobalVariable *>::iterator it;
    FunctionType *turn_on_compart_flag_ft = FunctionType::get(irBuilder.getVoidTy(),
                                                        {irBuilder.getVoidTy()},
                                                        false);
    FunctionCallee turn_on_compart_flag_func = parentModule->getOrInsertFunction(turn_on_compart_flag, 
                                                                                turn_on_compart_flag_ft);

    assert(turn_on_compart_flag_func && "can't get turn_on_Compart_flag_func function");

    irBuilder.CreateCall(turn_on_compart_flag_func, {});
    
    for (it = globalVarSet.begin(); it != globalVarSet.end(); ++it) {
        GlobalVariable *gVarToRecord = *it;
        FunctionType *new_global_func_ft = FunctionType::get(irBuilder.getInt32Ty(),
                                            {irBuilder.getInt8PtrTy(),
                                            irBuilder.getInt64Ty()},
                                            false);
        FunctionCallee new_global_data_func = parentModule->getOrInsertFunction(new_global_data, 
                                                                                new_global_func_ft);

        assert(new_global_data_func && "can't get new_global_data function");

        Value *val = irBuilder.CreateLoad(irBuilder.getInt64Ty(), gVarToRecord);
        Value *globa_addr = irBuilder.CreateBitCast(gVarToRecord, irBuilder.getInt8PtrTy());
        irBuilder.CreateCall(new_global_data_func, 
                            {globa_addr,
                            val});
        // B.CreateCall();
    }
    isTransformed = true;
    errs() << "[Finish insert record inst in front of function]" << "\n";
}

void MemOpTransformation::insertRstoreFunc() {
    errs() << "[Perform insertRestoreFunc]" << "\n";

    BasicBlock *bb = &(funcToModified->back());
    Instruction *i = bb->getFirstNonPHI();
    
    IRBuilder<> irBuilder(i);
    FunctionType *restoreFt = FunctionType::get(irBuilder.getVoidTy(),
                                                {irBuilder.getVoidTy()},
                                                false);
    FunctionCallee restore_fuc = parentModule->getOrInsertFunction(restore,
                                                                    restoreFt);

    assert(restore_fuc && "can't get restore function");
    irBuilder.CreateCall(restore_fuc,
                        {});

}

namespace {
    struct MRRPass : public FunctionPass {
        static char ID;
        MRRPass() : FunctionPass(ID) {}

        bool runOnFunction(Function &F) override {
            MemOpTransformation transformation(F);
            if (!transformation.isFunctionToSkip())
                transformation.performTransformation();
            // errs() << getPassName() << "\n";
            return transformation.isFuncTransformed();
        } ;
    };

}
Pass *llvm::MRR::createMrrPass() {
    return new MRRPass();
}


char MRRPass::ID = 0;
