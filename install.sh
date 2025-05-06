#!/bin/bash

# Usage ./install.sh <AFL++ path> <github username> <github branch> <clang-version>
# TODO: More configuration if this becomes a viable method of fuzzing.

set -e

export CC=$1/afl-clang-fast
export CXX=$1/afl-clang-fast++
export LD=$1/afl-clang-fast

# Fetch the remote bitcoin branch and build it.
git clone https://github.com/$2/bitcoin -b $3 --single-branch
# TODO: Target patch disable -fcf-protection
(cd bitcoin && cmake -B build_fuzz -DBUILD_FOR_FUZZING=ON -DENABLE_HARDENING=OFF -DAPPEND_CPPFLAGS="-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -DSNAPSHOT_FUZZ" && cmake --build build_fuzz -j16)

export CC=
export CXX=
export LD=

# Create nyx_bitcoin_agent.so
(cd src && clang-$4 -fPIC -D_GNU_SOURCE -DNO_PT_NYX agent.c -ldl -I. -shared -o nyx_bitcoin_agent.so)

# Remove polluted directories so we don't prematurely fail.
rm -rf /tmp/fuzzsharedir
rm -rf /tmp/out

# Create and populate the share directory.
mkdir /tmp/fuzzsharedir
(cd src && python3 ./create_sharedir.py --sharedir=/tmp/fuzzsharedir --target=cmpctblock --binary=bitcoin/build_fuzz/bin/fuzz)

# Build nyx tools
# TODO: Currently the script assumes nyx tools are built.

# Copy over nyx-related binaries and generate the nyx config/
cp $1/nyx_mode/packer/packer/linux_x86_64-userspace/bin64/* /tmp/fuzzsharedir
python3 $1/nyx_mode/packer/packer/nyx_config_gen.py /tmp/fuzzsharedir Kernel -m 4096

# Copy over the fuzz binary and nyx_bitcoin_agent.so
cp bitcoin/build_fuzz/bin/fuzz /tmp/fuzzsharedir
cp nyx_bitcoin_agent.so /tmp/fuzzsharedir

# TODO: Sample entry to /tmp/in instead of assuming existence.
AFL_PATH=$1 afl-fuzz -X -i /tmp/in -o /tmp/out -- /tmp/fuzzshared
