add_executable(precondInfer
        backward-ai.cpp
        )

set(LLVM_COMPONENTS
        irreader
        )

klee_get_llvm_libs(LLVM_LIBS ${LLVM_COMPONENTS})
target_link_libraries(precondInfer ${LLVM_LIBS} backwardAI)

install(TARGETS precondInfer RUNTIME DESTINATION bin)