#!/bin/bash
set -e

# check ${BEACON}
if [[ -z "$BEACON" ]]; then
  echo "Error: BEACON is not set"
  exit 1
elif [[ ! -d "$BEACON" ]]; then
  echo "Error: BEACON:$BEACON directory does not exist"
  exit 1
fi

$BEACON/afl-fuzz -i $BEACON/Test/fuzz_in -o $BEACON/Outputs/fuzz_out -m none -t 9999 -d -- $BEACON/Outputs/CVE-2017-7578 @@