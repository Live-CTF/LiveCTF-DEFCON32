#!/bin/bash

set -e

HANDOUT_FILES=(
    "./build/challenge"
    "./src/backdoor.py"
    "./src/gen.py"
)

# Build binaries
gcc -o build/challenge -O1 src/challenge.c

# Copy required files to handout
for f in ${HANDOUT_FILES[@]}; do
    cp $f handout/
done
