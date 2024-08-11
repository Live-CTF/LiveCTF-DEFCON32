#!/bin/bash

set -e

mkdir -p output

# Build binaries
gcc -O0 -no-pie -Wall -o output/challenge src/challenge.c
