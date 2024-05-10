#!/bin/bash

set -e

HANDOUT_FILES=(
    "./src/runner.py"
)

# We build the binaries locally :P
# # Build binaries
# python3 ./src/make.py

# Copy required files to handout
for f in ${HANDOUT_FILES[@]}; do
    cp $f handout/
done

mkdir handout/bins
cp ./src/bins/qrackme_{0,1,2,3,4} handout/bins/
