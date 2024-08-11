#!/bin/bash

set -e

HANDOUT_FILES=(
    "./build/challenge"
    "/lib/x86_64-linux-gnu/libc.so.6"
    "/lib64/ld-linux-x86-64.so.2"
)

mkdir -p build handout

# Build binaries
# Use PIE and partial relro for easy GOT redirection
gcc src/challenge.c -Wl,-z,relro,-z,lazy -g -O0 -fno-stack-protector -w -o build/challenge
# Original: no PIE, so no leak needed
# gcc src/challenge.c -g -O0 -fno-stack-protector -no-pie -Wall -o build/challenge

# Copy required files to handout
for f in ${HANDOUT_FILES[@]}; do
    cp $f handout/
done
