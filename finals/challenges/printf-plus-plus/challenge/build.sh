#!/bin/bash

set -e

HANDOUT_FILES=(
    "./build/challenge"
    "/lib/i386-linux-gnu/libgcc_s.so.1"
    "/lib/i386-linux-gnu/libc.so.6"
    "/lib/i386-linux-gnu/libm.so.6"
    "/lib32/libstdc++.so.6"
    "/lib/ld-linux.so.2"
)

# Build binaries
cmake -S src -B build
cmake --build build

# Copy required files to handout
for f in ${HANDOUT_FILES[@]}; do
    cp $f handout/
done
