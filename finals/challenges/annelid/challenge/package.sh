#!/bin/bash

set -e

HANDOUT_FILES=(
    "/home/livectf/challenge"
    "/lib/x86_64-linux-gnu/libc.so.6"
    "/lib64/ld-linux-x86-64.so.2"
)

TMPDIR=$(mktemp -d)
# Copy required files to handout
for f in ${HANDOUT_FILES[@]}; do
    cp "$f" "$TMPDIR/"
done

tar -C "$TMPDIR" -czvf "/handout.tar.gz" "."
