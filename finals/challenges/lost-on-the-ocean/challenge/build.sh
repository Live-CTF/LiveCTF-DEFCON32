#!/bin/bash

set -e

HANDOUT_FILES=(
    "./build/crackme"
    "./src/server.py"
)

mkdir -p build handout

# Build binaries
python3 src/generate.py > src/challenge.prg
hbmk2 -fullstatic -hbexe -std -obuild/crackme src/challenge.prg

ls -al build

# Copy required files to handout
for f in ${HANDOUT_FILES[@]}; do
    cp $f handout/
done
