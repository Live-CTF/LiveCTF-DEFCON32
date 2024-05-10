#!/usr/bin/env python3

from pwn import *
from base64 import b64decode
import subprocess

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

io = remote(HOST, int(PORT))

def main():
    for _ in range(5):
        io.recvuntil(b": ")
        encoded = io.recvline(keepends=False)
        decoded = b64decode(encoded)

        with open("prob", "wb") as f:
            f.write(decoded)
        os.chmod("prob", 0o777)
        p = process(["python3", "/auto.py"])
        p.recvuntil(b"ans: ")
        result = p.recvline().strip()[2:-1]
        p.close()
        print(result)
        io.sendlineafter(b": ", result)
        print(io.recvline())
    
    io.sendline(b"./submitter")
    flag = io.recvline_contains(b'LiveCTF{').decode().strip()
    log.info('Flag: %s', flag)

if __name__ == "__main__":
    main()
