# 1. Introduction
This directory provides the source code of the paper: "BEACON: Directed Grey-Box Fuzzing with Provable Path Pruning"[[S&P 2022](https://ieeexplore.ieee.org/document/9833751)].

# 2. Run Beacon
## 2.1 Environment Prerequisite
### 2.1.1 Set Environment Variable
```export BEACON=<path_of_beacon_repository>```
### 2.1.2 Install Dependent Tools
You could run `$BEACON/scripts/preinstall.sh` to install the dependent tools.
```
apt-get update --fix-missing
apt-get install -y make build-essential git wget cmake gawk libtinfo-dev libcap-dev zlib1g-dev

# llvm-4.0
apt-get install -y libtinfo5
apt-get install -y xz-utils
wget -q https://releases.llvm.org/4.0.0/clang+llvm-4.0.0-x86_64-linux-gnu-ubuntu-16.10.tar.xz
tar -xf clang+llvm-4.0.0-x86_64-linux-gnu-ubuntu-16.10.tar.xz
rm clang+llvm-4.0.0-x86_64-linux-gnu-ubuntu-16.10.tar.xz
cp -r clang+llvm-4.0.0-x86_64-linux-gnu-ubuntu-16.10 /usr/llvm
cp -r /usr/llvm/bin/* /usr/bin
cp -r /usr/llvm/lib/* /usr/lib
cp -r /usr/llvm/include/* /usr/include
cp -r /usr/llvm/share/* /usr/share

# wllvm
apt-get install -y python3 python3-dev python3-pip
pip3 install --upgrade pip
pip3 install wllvm
```
## 2.2 Build Beacon
You could run `$BEACON/scripts/build.sh` to install the dependent tools.
### 2.2.1 Build SVF
```
git clone https://github.com/SVF-tools/SVF.git
pushd SVF
git reset --hard 3170e83b03eefc15e5a3707e5c52dc726ffcd60a
sed -i 's/LLVMRELEASE=\/home\/ysui\/llvm-4.0.0\/llvm-4.0.0.obj/LLVMRELEASE=\/usr\/llvm/' build.sh
./build.sh
popd
```
### 2.2.2 Build Precondition Inference Engine (precondInfer)
```
pushd precondInfer
mkdir build
pushd build
cmake \
	-DENABLE_KLEE_ASSERTS=ON \
	-DCMAKE_BUILD_TYPE=Release \
	-DLLVM_CONFIG_BINARY=/usr/bin/llvm-config \
	-DSVF_ROOT_DIR=$FUZZER/repo/SVF \
	-DSVF_LIB_DIR=$FUZZER/repo/SVF/Release-build/lib \
	..
make -j
```
### 2.2.3 Build Instrumentation Engine (Ins)
```
pushd Ins
mkdir build
pushd build
CXXFLAGS="-fno-rtti" cmake \
	-DLLVM_DIR=/usr/lib/cmake/llvm/ \
	-DCMAKE_BUILD_TYPE=Release \
	..
make -j
popd
```
## 2.3 Instrument Binary
You could run `$BEACON/scripts/instrument.sh` to instrument the test binary.
It is recommended to run Beacon under a new folder `$BEACON/Outputs` to make sure the output files are gathered in a common folder.

```mkdir $BEACON/Outputs; cd $BEACON/Outputs```

### 2.3.1 Generate bitcode file
Generate the bitcode file for the target project.
In this repository, we have already provided a demo bc in `$BEACON/Test/swftophp-2017-7578.bc`. You could generate your own bitcode file by wllvm.
### 2.3.2 Static Analysis
```$BEACON/precondInfer/build/bin/precondInfer $BEACON/Test/swftophp-2017-7578.bc --target-file=$BEACON/Test/cstest.txt --join-bound=5```

**Inputs:**
- `$BEACON/Test/swftophp-2017-7578.bc` is the bitcode file for the target project.
- `$BEACON/Test/cstest.txt` has the following content `parser.c:66`, which means that the target for directed fuzzing is at Line 66 of parser.c. The target file must contain a single line of the form “fileName:lineNum”.

**Outputs:**
- `bbreaches.txt`: the set of basic blocks reachable to the target inst.
- `range_res.txt`: range analysis result.
- `transed.bc`: The slightly transformed bc for further processing.

**Caveats:**
Beacon uses the debug information in the LLVM IR to find the location in IR that corresponds to the source code location given in the target file. Therefore, the given bitcode should contain debug information. Also, since one source code line can map to multiple LLVM instructions, the target instruction located by Beacon is simply one of those instructions. Finally, the current implementation does not allow the target instruction to be a Phi Instruction.

The target location process can be described using the following pseudo code:
```jsx
Given (filename, linenum) in the target file
for each instruction I in the given bc:
  let (debug_file, debug_line)
      be the file name and line number of I recovered from debug information
  if (filename is a substring of debug_file) && (linenum == debug_line)
    treat I as the target instruction and start the static analysis
```

Users should supply a “good” source code location in the target file. Beacon will not proceed if the supported target file is illegal.

### 2.3.3 Instrumentation
```$BEACON/Ins/build/Ins -output=$BEACON/Outputs/CVE-2017-7578.bc -blocks=$BEACON/Outputs/bbreaches.txt -afl -log=log.txt -load=$BEACON/Outputs/range_res.txt ./transed.bc```

The instrumentation tool will take the above three files and output an instrumented bc.

In this example:
- **output** is the output location for the instrumented bc files. E.g., `swftophp-2017-7578.bc` is the instrumented bitcode file for the target project.
- **blocks** receives the lists of the reachable blocks from a file. E.g., `bbreaches.txt` is reachable blocks inferred from the previous analysis. The form could vary based on byte code or source code.
- **load** receives the lists of the preconditions from a file. E.g., `range_res.txt` is the preconditions inferred from the previous analysis.
- **afl** enable the instrumentation for AFL coverage tracing.
- `transed.bc` is the _transfromed_ bc from the previous analysis.

### 2.3.4 Compilation
Since we have the bc with the infeasible path pruned, we need to compile the bc into an executable binary.

```clang $BEACON/Outputs/CVE-2017-7578.bc -o $BEACON/Outputs/CVE-2017-7578 -lm -lz $BEACON/Fuzzer/afl-llvm-rt.o```

## 2.4 Fuzzing
Finally, fuzz all the things!
You could run `$BEACON/scripts/run.sh` to fuzz the test binary.

```$BEACON/Fuzzer/afl-fuzz -i $BEACON/Test/fuzz_in -o $BEACON/Outputs/fuzz_out -m none -t 9999 -- $BEACON/Outputs/CVE-2017-7578 @@```

# 3. Docker Images
Alternatively, you could use [docker image](https://hub.docker.com/r/yguoaz/beacon) (Beacon binary without source code)

# 4. FAQ

## 1. The precision of the static analysis (Help wanted) 
The static analysis could influence both reachability analysis and precondition inference to prune infeasible paths, especially for handling indirect calls. The released prototype utilizes a flow-sensitive Anderson pointer analysis. The reachability results can be varied with different pointer analyses and influence the performance of Beacon. 
Moreover, we noticed that with better static reachability analysis, e.g., an upgraded version of SVF with a higher LLVM version, the results can improved with minor analysis overhead. You can also try our [script](scripts/icfg_index.py) for reachability analysis based on the dot files exported by any version of SVF, which could have better precision and is used in the evaluation for the paper. We are also looking forward to any optimized static analysis techniques proposed to improve Beacon! Drop me an email (hhuangaz at cse dot ust dot hk) if you have any thoughts or ideas ~ 

In practice, there are also some engineering issues requiring more specifications for system and library functions, which cannot be seen in the control flow graph extracted from LLVM IR for reachability analysis. We have encountered the issue of AFL reporting `no instrumentation`. In this case, one of the straightforward solutions is not to use the parameter “-block” in this case during the instrumentation stage. You can also add more specifications for some library or system functions that do not appear in the control flow graph obtained to ensure paths won't get falsely pruned.

## 2. Supporting other fuzzers   
Our prototype can generate the target binary that can be **directly used for other AFL-based fuzzers** as the paper said. The [prototype in Dockerhub](https://hub.docker.com/r/yguoaz/beacon) is a unique version for our assessing environment, which **does not** work with other fuzzers. For general purposes, you should **use our released code** to generate the binary for other AFL-based fuzzers. You can also modify the instrumentation code to support your own features. In this case, please use your own ``afl-llvm-rt.o`` as well.

We find there are some compatibility issues to generate a whole bc to analyze when serving for Libfuzzer-based fuzzers with an additional afldriver.cpp. If you are willing to help, please let me know through email (hhuangaz at cse dot ust dot hk).

# 5. Publication
You can find more details in our S&P 2022 paper.
```
@INPROCEEDINGS{9833751,
  author={Huang, Heqing and Guo, Yiyuan and Shi, Qingkai and Yao, Peisen and Wu, Rongxin and Zhang, Charles},
  booktitle={2022 IEEE Symposium on Security and Privacy (SP)}, 
  title={BEACON: Directed Grey-Box Fuzzing with Provable Path Pruning}, 
  year={2022},
  volume={},
  number={},
  pages={36-50},
  doi={10.1109/SP46214.2022.9833751}}
```

# 5. License
Beacon is under [Apache License](https://github.com/qhjchc/BeaconOpenSource/blob/main/LICENSE).
