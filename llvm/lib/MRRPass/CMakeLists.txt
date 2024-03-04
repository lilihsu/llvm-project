add_llvm_library( MRRPass
MRRPass.cpp

	ADDITIONAL_HEADER_DIRS
	${LLVM_MAIN_INCLUDE_DIR}/llvm/MRRPass
	${LLVM_MAIN_INCLUDE_DIR}/llvm/Support
	${LLVM_MAIN_INCLUDE_DIR}/llvm/IR

	DEPENDS
	intrinsics_gen
	LLVMCore
	LLVMSupport
	LLVMTransformUtils
	LLVMCodeGen

	LINK_LIBS
	LLVMCore
	LLVMSupport
	LLVMTransformUtils
	LLVMCodeGen
	)

set_property(TARGET MRRPass PROPERTY LLVM_SYSTEM_LIBS)