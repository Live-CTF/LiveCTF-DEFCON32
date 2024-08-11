#!/bin/bash

set -e

HANDOUT_FILES=(
    "/home/livectf/server.py"
)

TMPDIR=$(mktemp -d)
# Copy required files to handout
for f in ${HANDOUT_FILES[@]}; do
    cp "$f" "$TMPDIR/"
done

tar -C "$TMPDIR" -czvf "/handout.tar.gz" "."
