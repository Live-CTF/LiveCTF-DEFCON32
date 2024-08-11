#!/usr/bin/env python3

import pickle
import arc4

password = input("What is the password? ")
encrypted_flag = bytes.fromhex("%s")
encrypted_flag = pickle.loads(encrypted_flag)

rc4 = arc4.ARC4(password.encode())
flag = rc4.decrypt(encrypted_flag).decode()
print(f"Flag: {flag}")
