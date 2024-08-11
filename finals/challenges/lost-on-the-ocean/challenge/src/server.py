#!/usr/bin/env python3

import subprocess
import os


password = input("What is the password? ").strip()

result = subprocess.check_output(["./crackme", password])
if b"Correct!" in result:
    print("Correct!")
    os.system("/bin/sh")
else:
    print("Incorrect!")
