cmake_minimum_required(VERSION 2.8.12)
project(test-ai)

set(ENV{LLVM_HOME} /Users/huangdoudou/Dependence/llvm-10.0.0.src/release-build)
set(ENV{LLVM_DIR} $ENV{LLVM_HOME}/lib/cmake/llvm)

find_package(LLVM REQUIRED CONFIG)
add_definitions(${LLVM_DEFINITIONS})
include_directories(${LLVM_INCLUDE_DIRS})
include_directories(${SVF_HEADER})
include_directories(SYSTEM /Users/huangdoudou/Dependence/clang/include SYSTEM /Users/huangdoudou/Dependence/clang/include SYSTEM ${LLVM_CONFIG_INCLUDE_DIR})
link_directories(${LLVM_LIBRARY_DIRS})

find_package(LLVM REQUIRED CONFIG)
add_definitions(${LLVM_DEFINITIONS})
include_directories(${LLVM_INCLUDE_DIRS})

find_package(LLVM REQUIRED CONFIG)
add_definitions(${LLVM_DEFINITIONS})

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c++11")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -fno-rtti")

add_executable(Ins main.cpp deserialize.cpp deserialize.h)
llvm_map_components_to_libnames(llvm_libs core support passes irreader bitwriter)

target_link_libraries(Ins ${llvm_libs})


