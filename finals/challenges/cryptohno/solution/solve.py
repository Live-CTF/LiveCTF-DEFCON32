from pwn import *

import argparse
import binascii
import gmpy2
import secrets


exe = ELF('../../../handouts/cryptohno/handout/challenge')
context.binary = exe
context.terminal = ['alacritty', '-e', 'bash', '-c']

LOCAL = False

parser = argparse.ArgumentParser()
parser.add_argument("address", default="127.0.0.1:8001", help="Address of challenge")

args = parser.parse_args()
HOST, PORT = args.address.split(':')
PORT = int(PORT)


# From https://cryptohack.gitbook.io/cryptobook/untitled/recovering-the-modulus
"""
@param pairings
    list: [(pt1, ct1), (pt2, ct2), ..., (ptk, ctk)]
@param e
    int : encryption exponent
@return
    int : recovered N
"""
def recover_n(pairings, e):
    pt1, ct1 = pairings[0]
    N = ct1 - pow(pt1, e)

    # loop through and find common divisors
    for pt,ct in pairings:
        val = gmpy2.mpz(ct - pow(pt, e))
        N = gmpy2.gcd(val, N)

    return N

if LOCAL:
    r = process([exe.path])
else:
    r = remote(HOST, PORT)


def rotate_key():
    r.sendlineafter(b'> ', b'1')


def encrypt(ptxt: bytes):
    r.sendlineafter(b'> ', b'2')
    r.sendlineafter(b'input: ', ptxt)
    ptxt_int = int.from_bytes(ptxt)
    r.recvuntil(b'ctxt: ')
    ctxt_int = int(r.recvline().strip(), 16)
    return (ptxt_int, ctxt_int)


def encrypt_flag():
    r.sendlineafter(b'> ', b'3')
    r.recvuntil(b'ctxt: ')
    return int(r.recvline().strip(), 16)


def win(pw: bytes):
    r.sendlineafter(b'> ', b'4')
    r.sendlineafter(b'password: ', pw)


while True:
    rotate_key()
    # rotate key until p is not prime
    output = r.recvuntil(b'1.')
    if b'p is not prime' in output:
        break


pairings = [encrypt(secrets.token_hex(4).encode()) for _ in range(5)]

e = 65537
n = recover_n(pairings, e)

assert n != 1

p = gmpy2.isqrt(n)

assert p*p == n

phi = p*(p-1)
d = pow(e, -1, phi)
enc_pw = encrypt_flag()
dec_pw = pow(enc_pw, d, n)

pw_bytes = binascii.unhexlify(hex(dec_pw)[2:])

win(pw_bytes)

assert b'You win' in r.recvline()

r.sendline(b'./submitter')
r.interactive()
