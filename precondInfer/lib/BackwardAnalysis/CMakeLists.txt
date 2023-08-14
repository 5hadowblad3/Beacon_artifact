klee_add_component(backwardAI
        BackwardAnalysis.cpp
        AbstractState.cpp
        WPCondition.cpp
        WPInferenceInterface.cpp
        AliasICFG.cpp
        InstructionDbgInfo.cpp
        RangeAnalysis.cpp
        RangeComputeInterface.cpp
        )
set(LLVM_COMPONENTS
        core
        support
        passes
        bitwriter
        )

find_library(SVF_LIB libLLVMSvf.a HINTS ${SVF_LIB_DIR})
find_library(CUDD_LIB libLLVMCudd.a HINTS ${SVF_LIB_DIR}/CUDD)
message(STATUS "Note: ${SVF_LIB}")
message(STATUS "Note: ${CUDD_LIB}")

klee_get_llvm_libs(LLVM_LIBS ${LLVM_COMPONENTS})
target_link_libraries(backwardAI PUBLIC ${SVF_LIB} ${CUDD_LIB} ${LLVM_LIBS})
target_link_libraries(backwardAI PRIVATE
        kleeSupport
        kleaverExpr
        )

target_include_directories(backwardAI PUBLIC
        ${SVF_ROOT_DIR}/include
        )
