#!/usr/bin/env/python3
# powerprove

from pwn import *


def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m


HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

p = remote(HOST, int(PORT))
#p = process("../handout/challenge")

p.sendline(b"5")
p.recvuntil(b"xt\": ")
ctxt = p.recvuntil(b",")[:-1]
p.recvuntil(b"n\": ")
n = p.recvuntil(b"}")[:-1]

'''
payload = b"4 "
payload += b"{\"hash\":"
payload += hash_
payload += b",\"ctxt\":"
payload += ctxt
payload += b"}"

p.sendline(payload)

p.interactive()
'''

m1 = {
        "ctxt": int(ctxt),
        "n":int(n)
        }

# 'ls' encryption message

c1 = m1['ctxt']
n = m1['n']
n_sq = n**2
ls_inv = modinv(int.from_bytes(b'ls', 'big'), n)

target_str = b'./submitter'
submitter_hash = int(hashlib.sha256(target_str).hexdigest(), 16)
target_str_int = int.from_bytes(target_str, 'big')
target_str_int_mul_ls_inv = (target_str_int * ls_inv) % n_sq
c_target_str = pow(c1, target_str_int_mul_ls_inv, n_sq)



payload = b"4 "
payload += b"{\"hash\":"
payload += str(submitter_hash).encode()
payload += b",\"ctxt\":"
payload += str(c_target_str).encode()
payload += b"}"

p.sendline(payload)
sleep(0.5)
print(p.recvuntil(b"}"))

