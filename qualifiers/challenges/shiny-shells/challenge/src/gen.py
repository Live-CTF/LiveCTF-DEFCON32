import json
import math
import random

from cryptography.hazmat.primitives.asymmetric import rsa

while True:
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    pk = key.private_numbers()
    p = pk.p
    q = pk.q

    n = p*q
    n_2 = n**2

    if math.gcd(n, (p-1)*(q-1)) != 1:
        continue

    l = math.lcm(p-1, q-1)
    g = random.randrange(1, n_2)
    try:
        mu = pow(((pow(g, l, n_2)-1)//n), -1, n)
    except:
        continue

    break

with open('key.json', 'w') as f:
    json.dump({'p': p, 'q': q, 'g': g}, f)
