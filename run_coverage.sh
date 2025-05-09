#!/bin/bash

# Usage: ./run_coverage.sh <clang-version> <github username> <github branch> <corpus github> <llvm-bin-path> <fuzz-harness-name>
# TODO: De-duplicate logic in common with install.sh

set -e

export CC=clang-$1
export CXX=clang++-$1

# Fetch the remote bitcoin branch and build it.
git clone https://github.com/$2/bitcoin -b $3 --single-branch
(cd bitcoin && cmake -B build_fuzzcov -DBUILD_FOR_FUZZING=ON -DAPPEND_CFLAGS="-fprofile-instr-generate -fcoverage-mapping" -DAPPEND_CXXFLAGS="-fprofile-instr-generate -fcoverage-mapping" -DAPPEND_LDFLAGS="-fprofile-instr-generate -fcoverage-mapping" && cmake --build build_fuzzcov -j16)

export CC=
export CXX=

# Make the profile directory.
mkdir -p bitcoin/build_fuzzcov/raw_profile_data

# Copy over the corpus.
git clone https://github.com/$2/$4

LLVM_PROFILE="$PWD/bitcoin/build_fuzzcov/raw_profile_data/%m_%p.profraw" FUZZ="$6" bitcoin/build_fuzzcov/bin/fuzz $4/$6

find bitcoin/build_fuzzcov/raw_profile_data -name "*.profraw" | xargs $5/llvm-profdata-$1 merge -o bitcoin/build_fuzzcov/coverage.profdata

$5/llvm-cov-$1 show --object=bitcoin/build_fuzzcov/bin/fuzz -Xdemangler=$5/llvm-cxxfilt-$1 --instr-profile=bitcoin/build_fuzzcov/coverage.profdata --ignore-filename-regex="src/crc32c/|src/leveldb/|src/minisketch/|src/secp256k1/|src/test/" --format=html --show-instantiation-summary --show-line-counts-or-regions --show-expansions --output-dir=bitcoin/build_fuzzcov/coverage_report --project-title="fuzzcov"

