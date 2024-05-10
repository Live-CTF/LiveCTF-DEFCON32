#!/bin/bash

set -e

HANDOUT_FILES=(
    "./build/challenge"
    "/lib/x86_64-linux-gnu/libc.so.6"
    "/lib/x86_64-linux-gnu/libseccomp.so.2"
    "/lib64/ld-linux-x86-64.so.2"
)

# Build binaries
gcc -o build/challenge -Os -Wl,-z,norelro src/challenge.c -lseccomp

# Copy required files to handout
for f in ${HANDOUT_FILES[@]}; do
    cp $f handout/
done
