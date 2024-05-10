from pathlib import Path
from glob import glob
import base64
import os
import random
import subprocess

NUM_ROUNDS = 5

filelist = glob("./bins/qrackme_*")

for f in random.sample(filelist, k=NUM_ROUNDS):
    data = Path(f).read_bytes()
    print(f"File: {base64.b64encode(data).decode('charmap')}\n")

    # execute file with user input
    res = subprocess.run([str(f)])

    # check response
    if res.returncode != 0:
        print("Fail :(")
        exit(1)

print("You win!")
os.system("/bin/bash")
