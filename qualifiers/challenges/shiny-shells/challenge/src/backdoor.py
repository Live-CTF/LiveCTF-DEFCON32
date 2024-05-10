import hashlib
import json
import random
import subprocess
import sys

from math import gcd, lcm

with open('key.json', 'r') as f:
    key = json.load(f)

p: int = key['p']
q: int = key['q']
g: int = key['g']

n = p*q
n_sq = n**2
lam = lcm(p-1, q-1)
L = lambda x: (x-1)//n
mu = pow(L(pow(g, lam, n_sq)), -1, n)

def dec(ptxt_hash: int, ctxt: int) -> bytes:
    assert 0 < ctxt < n_sq
    ptxt_int = (((pow(ctxt, lam, n_sq) - 1) // n) * mu) % n
    ptxt_hex = format(ptxt_int, 'x')
    if len(ptxt_hex) % 2:
        ptxt_hex = '0' + ptxt_hex
    ptxt = bytes.fromhex(ptxt_hex)
    hash_int = int(hashlib.sha256(ptxt).hexdigest(), 16)
    assert hash_int == ptxt_hash
    return ptxt

def run(msg: dict):
    ptxt = dec(msg['hash'], msg['ctxt'])
    subprocess.run(ptxt.split())

if len(sys.argv) == 1:
    ptxt = b'ls'
    h = int(hashlib.sha256(ptxt).hexdigest(), 16)
    while True:
        r = random.randrange(1, n)
        if gcd(r, n) == 1:
            break
    ctxt = (pow(g, int.from_bytes(ptxt, 'big'), n_sq) * pow(r, n, n_sq)) % n_sq
    msg = {'hash': h, 'ctxt': ctxt, 'n': n}
    print(json.dumps(msg))
    run(msg)
else:
    run(json.loads(sys.argv[1]))
