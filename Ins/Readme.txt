mkdir build
cd build
CXXFLAGS="-fno-rtti" cmake -DLLVM_DIR=/path/to/llvm/build/ -DCMAKE_BUILD_TYPE=Release ../source/
make
