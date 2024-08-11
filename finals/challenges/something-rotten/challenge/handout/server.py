#!/usr/bin/env python3

import os
from Crypto.Protocol.KDF import PBKDF2

TARGET = "52a5ca720c05e0ba542899d4552c3e44"

flag = input("Flag: ")
flag_hash = PBKDF2(flag, b"something-rotten-flag", count=10000)
if flag_hash == bytes.fromhex(TARGET):
    print("Well done! Have a shell!")
    os.system("/bin/sh")
else:
    print("Invalid flag")
