#!/bin/bash

set -e

HANDOUT_FILES=(
    "./build/challenge.exe"
    "/opt/wine-stable/lib64/wine/x86_64-windows/kernel32.dll"
    "/opt/wine-stable/lib64/wine/x86_64-windows/msvcrt.dll"
)

# Build binaries
x86_64-w64-mingw32-gcc src/challenge.c -Wall -o build/challenge.exe
cp src/challenge.sh build/challenge

# Copy required files to handout
for f in ${HANDOUT_FILES[@]}; do
    cp -L $f handout/
done
