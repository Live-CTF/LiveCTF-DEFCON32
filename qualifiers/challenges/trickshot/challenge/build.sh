#!/bin/bash

set -e

HANDOUT_FILES=(
    "./build/trickshot"
    "./src/challenge.py"
)

# Build binaries
gcc src/main.c -O0 -o build/trickshot

# Copy required files to handout
for f in ${HANDOUT_FILES[@]}; do
    cp $f handout/
done
