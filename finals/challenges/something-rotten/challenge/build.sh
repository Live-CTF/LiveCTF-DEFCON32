#!/bin/bash

set -e

HANDOUT_FILES=(
    "./build/challenge.py"
    "./build/server.py"
)

mkdir -p build handout

# Build binaries
python3 src/generate.py

# Copy required files to handout
for f in ${HANDOUT_FILES[@]}; do
    cp $f handout/
done
