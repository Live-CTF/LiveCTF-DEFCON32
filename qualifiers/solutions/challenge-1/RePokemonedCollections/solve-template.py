#!/usr/bin/env python3

from pwn import *
import hashlib as h
import re
import json

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

def int_to_bytes(n: int) -> bytes:
    return n.to_bytes((n.bit_count() + 7) // 8, byteorder='big')

def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, byteorder='big')

# CMD = b'cat config.toml'
CMD = b'./submitter'


def main():
    io = remote(HOST, int(PORT))

    # io = process("cd ../handout/; ./challenge", shell=True)

    io.recvuntil(b"> ")
    io.sendline(b"5")

    # l = io.recvline()
    # print(l)
    io.recvuntil(b"{")
    k = json.loads(b"{" + io.recvline())

    ctxt = k["ctxt"]
    n = k["n"]
    n_sq = n ** 2

    power = pow(27763, -1, n_sq) * bytes_to_int(CMD) % n_sq
    new_ctxt = pow(ctxt, power, n_sq)

    hash = int(hashlib.sha256(CMD).hexdigest(), 16)

    io.recvuntil(b"> ")
    io.sendline(b"4 " + json.dumps({"ctxt": new_ctxt, "hash": hash}).encode())
    print(io.recvline().decode())
    # io.recvuntil(b"flag")
    # print(re.search(r'".*"', io.recvline().decode()).group(0))

    # io.interactive()

if __name__ == "__main__":
    main()
