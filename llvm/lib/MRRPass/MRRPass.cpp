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
    "kmem_cache_alloc",
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
const StringRef get_global_data = "get_global_data";
const StringRef set_mem_obj = "set_mem_obj";
const StringRef invalid_mem_obj = "invalid_mem_obj";
const StringRef new_field = "new_field";
const StringRef set_field = "set_field";
const StringRef get_field = "get_field";

MemOpTransformation::MemOpTransformation(Function &F) {
    if (funcs_to_instrument.find(F.getName()) == funcs_to_instrument.end()) {
        isSkiped = true;
        // errs() << "[skipped function name]:" << F.getName() << "\n";
        return;
    }

    parentModule = F.getParent(); 
    funcToModified = &F;
    collectGlobalVars();
    if (F.getName() == syscall_root) {
        isRootFunc = true;
        errs() << "[Find root function]:" << F.getName() << "\n";
    }
    collectInstsUseGlobal();
    collectRetInsts();
    collectKernelMemCallee();
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
            errs() << *load << "\n";
            return true;
        }
    }

    return false;
}

bool MemOpTransformation::isInstStoreGvars(StoreInst *store) {
    if (GlobalVariable * gvar = dyn_cast<GlobalVariable>(store->getPointerOperand())) {
        if (globalVarSet.find(gvar) != globalVarSet.end()) {
            errs() << *store << "\n";
            return true;
        }
    }

    return false;
}

void MemOpTransformation::collectInstsUseGlobal() {
    errs() << "[Analysis] collect inst using gVars" << "\n";
    for (auto it = inst_begin(funcToModified); it != inst_end(funcToModified); ++it) {
        Instruction *inst = &*it;

        if (LoadInst *load = dyn_cast<LoadInst> (inst)) {
            if (isInstLoadGvars(load))
                instLoadGvars.insert(inst);
        } else if (StoreInst *store = dyn_cast<StoreInst>(inst)) {
            if (isInstStoreGvars(store))
                instStoreGvars.insert(inst);
        }
    }
    
}

void MemOpTransformation::collectRetInsts(){
    errs() << "[Analysis] collect ret inst" << "\n";
    for (auto it = inst_begin(funcToModified); it != inst_end(funcToModified); ++it) {
        Instruction *inst = &*it;

        if (ReturnInst *ret = dyn_cast<ReturnInst> (inst)) {
            retInsts.insert(inst);
        }
    }
}

void MemOpTransformation::collectKernelMemCallee() {
    errs() << "[Analysis] collect kernel mem operation callee" << "\n";

    for (auto it = inst_begin(funcToModified); it != inst_end(funcToModified); ++it) {
        Instruction *inst = &*it;
        
        if (CallInst *callee = dyn_cast<CallInst>(inst)) {
            Function *calledFunc = callee->getCalledFunction();
            if (!calledFunc)
                continue;
            errs() << "call inst:" << calledFunc->getName() << "\n";
            StringRef funcName = calledFunc->getName();
            if (kernel_allocation_funcs.find(funcName) != kernel_allocation_funcs.end()) {
                memAllocCallees.insert(inst);
            }

            if (kernel_free_funcs.find(funcName) != kernel_free_funcs.end()) {
                memFreeCallees.insert(inst);
            }
        }

    }

}

void MemOpTransformation::performTransformation() {
    errs() << "[Transformation]: start to perform transformation";
    if (isRootFunction()) {
        insertGvarRecordInst();
        insertRstoreFunc();
        isTransformed = true;
    }

    if (!instLoadGvars.empty()) {
        replaceLoadGvarByGetter();
        isTransformed = true;
    }

    if (!instStoreGvars.empty()) {
        replaceStoreGvarBySetter();
        isTransformed = true;
    }

    if (!memAllocCallees.empty() && !memFreeCallees.empty()) {
        insertMemMonitor();
        isTransformed = true;
    }

    errs() << "[Transformation]: end of transformation";
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
    
    errs() << "[Finish insert record inst in front of function]" << "\n";
}

void MemOpTransformation::insertRstoreFunc() {
    errs() << "[Perform insertRestoreFunc]" << "\n";
    std::set<Instruction *>::iterator it;

    for (it = retInsts.begin(); it != retInsts.end(); ++it) {
        Instruction *i = *it;
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
    // BasicBlock *bb = &(funcToModified->back());
    // Instruction *i = bb->getFirstNonPHI();
}

void MemOpTransformation::replaceLoadGvarByGetter() {
    errs() << "[Perform replaceLoadGvarByGetter]";
    std::set<Instruction *>::iterator it;
                        
    errs() << "[Start to modify load inst]" << "\n";
    for (it = instLoadGvars.begin(); it != instLoadGvars.end(); it++) {
        Instruction *inst = *it;
        errs() << *inst << "\n";
        LoadInst *load = dyn_cast<LoadInst> (inst);
        IRBuilder <> irBuilder(inst);

        FunctionType *get_global_data_ty = FunctionType::get(irBuilder.getInt64Ty(),
                                            {irBuilder.getInt8PtrTy(),
                                            irBuilder.getInt64Ty()},
                                            false);
        FunctionCallee get_global_data_callee = parentModule->getOrInsertFunction(get_global_data,
                                                                                    get_global_data_ty);
        Value *gVar_addr = irBuilder.CreateBitCast(load->getPointerOperand(), irBuilder.getInt8PtrTy());
        CallInst *callInst = irBuilder.CreateCall(get_global_data_callee,
                             {gVar_addr});
        inst->replaceAllUsesWith(callInst);
        inst->eraseFromParent();
    }
}

void MemOpTransformation::replaceStoreGvarBySetter() {
    errs() << "[Perform replaceStoreGvarBySetter]";
    std::set<Instruction *>::iterator it;

    for (it = instStoreGvars.begin(); it != instStoreGvars.end(); it++) {
        Instruction *inst = *it;
        errs() << "[inst]:"<< *inst<< "\n";
        StoreInst *store = dyn_cast<StoreInst> (inst);
        IRBuilder <> irBuilder(inst);
        FunctionType *set_global_data_ty = FunctionType::get(irBuilder.getVoidTy(),
                                                            {irBuilder.getInt8PtrTy(),
                                                            irBuilder.getInt64Ty(),
                                                            },
                                                            false);
        errs() << "[Debug]: generate function type successfully" << "\n";
        FunctionCallee set_global_data_callee = parentModule->getOrInsertFunction(set_global_data,
                                                                                set_global_data_ty);
        errs() << "[Debug]: gnerate function callee successfully" << "\n";
        Value *store_var = store->getPrevNonDebugInstruction();
        Value *gVar_addr = irBuilder.CreateBitCast(store->getPointerOperand(), irBuilder.getInt8PtrTy());
        
        errs() << "[Debug] gVar_addr: " << *gVar_addr << "store_var: " << *store_var << "\n";
        CallInst * callInst = irBuilder.CreateCall(set_global_data_callee,
                                                    {gVar_addr,
                                                    store_var});
        errs() << "[Debug] created CallInst:" << *callInst << "\n";
        //inst->removeFromParent();
        inst->replaceAllUsesWith(callInst);
        inst->eraseFromParent();
    }

    errs() << "[Transformation]: finish replace store gVar with setter";
}

void MemOpTransformation::insertMemMonitor() {
    errs() << "[Transformation]: insert mem alloc free record function behind instruction" << "\n";
    std::set<Instruction *>::iterator it;
    Instruction *inst;

    for (it = memAllocCallees.begin(); it != memAllocCallees.end(); it++) {
        inst = *it;
        IRBuilder<> irBuilder(inst->getNextNode());
        FunctionType *set_mem_obj_ty = FunctionType::get(irBuilder.getInt32Ty(),
                                            {irBuilder.getInt8PtrTy(),
                                            irBuilder.getInt1Ty()},
                                            false);
        Value *mem_addr = dyn_cast<Value>(inst);
        FunctionCallee set_mem_obj_func = parentModule->getOrInsertFunction(set_mem_obj,
                                                                            set_mem_obj_ty);
        irBuilder.CreateCall(set_mem_obj_func,
                            {mem_addr,
                            irBuilder.getFalse()});
        
    }

    for (it =memFreeCallees.begin(); it != memFreeCallees.end(); it++) {
        inst = *it;
        
        IRBuilder<> irBuilder(inst->getNextNode());
        FunctionType *invalid_mem_obj_ty = FunctionType::get(irBuilder.getInt32Ty(),
                                                            {irBuilder.getInt8PtrTy()},
                                                            false);
        FunctionCallee invalid_mem_obj_func = parentModule->getOrInsertFunction(invalid_mem_obj,
                                                                            invalid_mem_obj_ty);
        CallInst *callInst = dyn_cast<CallInst>(inst);
        Value *mem_addr = callInst->getArgOperand(0);
        irBuilder.CreateCall(invalid_mem_obj_func,
                            {mem_addr});
    }
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
            //errs() << "[Function Pass]: finish run on function pass" << "\n";
            return transformation.isFuncTransformed();
        } ;
    };

}
Pass *llvm::MRR::createMrrPass() {
    return new MRRPass();
}


char MRRPass::ID = 0;
