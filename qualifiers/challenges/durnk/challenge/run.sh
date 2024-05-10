#!/bin/sh

sed -i "s/LiveCTF{PLACEHOLDER_FLAG}/$FLAG/" .config.toml
unset FLAG

socat TCP-LISTEN:31337,reuseaddr,fork EXEC:"./challenge"
