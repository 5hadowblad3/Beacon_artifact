#!/bin/bash
set -e
set -x

# check ${BEACON}
if [[ -z "$BEACON" ]]; then
  echo "Error: BEACON is not set"
  exit 1
elif [[ ! -d "$BEACON" ]]; then
  echo "Error: BEACON:$BEACON directory does not exist"
  exit 1
fi
pushd $BEACON

if [ ! -d Outputs ]; then
	mkdir Outputs; 
fi
pushd Outputs

$BEACON/precondInfer/build/bin/precondInfer $BEACON/Test/swftophp-2017-7578.bc --target-file=$BEACON/Test/cstest.txt --join-bound=5

$BEACON/Ins/build/Ins -output=$BEACON/Outputs/CVE-2017-7578.bc -blocks=$BEACON/Outputs/bbreaches.txt -afl -byte -log=log.txt -load=$BEACON/Outputs/range_res.txt ./transed.bc

clang $BEACON/Outputs/CVE-2017-7578.bc -o $BEACON/Outputs/CVE-2017-7578 -lm -lz $BEACON/afl-llvm-rt.o