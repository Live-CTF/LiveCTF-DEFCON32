#!/bin/bash

if [ $(cat /proc/sys/kernel/yama/ptrace_scope) -ne 0 ]; then
    sudo sh -c 'echo 0 > /proc/sys/kernel/yama/ptrace_scope'
fi

ROSETTA_DEBUGSERVER_PORT=1234 $1 & gdb --init-eval-command "set architecture i386:x86-64" --init-eval-command "file $1" --init-eval-command "target remote localhost:1234"
