#!/bin/bash

set -e

mkdir -p output

# Build binaries
gcc src/challenge.c -O0 -fno-stack-protector -no-pie -Wall -o output/challenge
