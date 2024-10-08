#!/bin/bash

set -e
mkdir -p build handout

HANDOUT_FILES=(
    "./build/challenge"
    "/lib/x86_64-linux-gnu/libc.so.6"
    "/lib64/ld-linux-x86-64.so.2"
    "./build/server.py"
)

FLAG='LiveCTF{you_truly_went_the_distance}'

# Build binaries
python3 src/encrypt.py src/flag "$FLAG" 32 128
gcc src/challenge.c src/rc4.c src/flag.c -Wall -Wpedantic -o build/challenge
#strip build/challenge

# Copy required files to handout
for f in ${HANDOUT_FILES[@]}; do
    cp $f handout/
done
