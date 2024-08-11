#!/usr/bin/env python3

from pwn import *
import math
import gmpy2
import re
#from Crypto.Util.number import getPrime

if True:
    io = process('../challenge/handout/challenge')
else:
    io = gdb.debug('../challenge/handout/challenge', '''
    #pie break 0x19e6
    #pie break 0x19eb
    continue
    ''')

def menu(io, choice):
    io.recvuntil(b'> ')
    io.sendline(f'{choice}'.encode())    

def init_key(io):
    menu(io, 1)
    result = io.recvline_contains([b'Error: ', b'1. Rotate Key']).decode().strip()
    if result.startswith('1. '):
        return None
    return re.match('Error: (p|q) is not prime', result)[1]

def encrypt_text(io, text):
    menu(io, 2)
    io.recvuntil(b'input: ')
    io.sendline(text)
    io.recvuntil(b'ctxt: ')
    ctxt = io.recvline().decode().strip()
    return int(ctxt, 16)

def encrypt_flag(io):
    menu(io, 3)
    io.recvuntil(b'ctxt: ')
    ctxt = io.recvline().decode().strip()
    return int(ctxt, 16)

def get_shell(io, password):
    menu(io, 4)
    io.recvuntil(b'password: ')
    io.sendline(password)

def extract_n(io):
    diffs = []
    for i in range(5):
        log.info('Encrypting %d', i)
        pt = ord('A')+i
        ct = encrypt_text(io, bytes([pt]))
        diffs.append(ct - pow(pt, 0x10001))

    return math.gcd(*diffs)


# Free first time
while True:
    res = init_key(io)
    if res:
        log.info('Found: %s not prime', res)
        break

# Free again
init_key(io)
init_key(io)

# Get N, calculate p==q
n = extract_n(io)
log.info('Extracted N: %x', n)

n2 = gmpy2.mpz(n)
gmpy2.get_context().precision=2048
p = int(gmpy2.sqrt(n2))
if p*p==n:
    log.info('Found p==q: %x', p)
else:
    log.error('Failed to find p==q')

e = 0x10001
flag_c = encrypt_flag(io)
log.info('Encrypted flag: %x', flag_c)
#phi = (p-1)*(p-1)
phi = (p-1)*p
d = pow(e, -1, phi)
flag_m = pow(flag_c, d, p*p)
log.info('Decrypted flag: %x', flag_m)

flag = flag_m.to_bytes(0x20, 'big')
get_shell(io, flag)


io.interactive()
