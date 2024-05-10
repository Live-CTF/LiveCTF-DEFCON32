import argparse
import base64
import string
import subprocess
import tempfile

from pwn import *

context.log_level = 'error'

alpha = string.ascii_letters + string.digits

print("DID IT START AT ALL??")

# Save binary, gdb it, pass input char at a time until instr count increases

parser = argparse.ArgumentParser()
default_addr = os.environ.get("HOST", "127.0.0.1") + ":" + os.environ.get("PORT", "31337")
parser.add_argument("address", default=default_addr, nargs="?", help="Address of challenge")
args = parser.parse_args()
HOST, PORT = args.address.split(':')

r = remote(HOST, int(PORT))

working = Path(tempfile.mktemp())
working.touch()
working.chmod(0o700)
print(working)

for round_num in range(5):
    print("Round", round_num)
    r.recvuntil(b'File: ')
    file_contents = base64.b64decode(r.recvline().strip())
    working.write_bytes(file_contents)

    known = []
    while len(known) < 8:
        best_guess = (b'', 0)
        guess = known + [b'A' for _ in range(8-len(known))]
        for i in alpha:
            guess[len(known)] = i.encode()
            #perf = process(["qemu-i386", "-d", "in_asm", "--", str(working)])
            # perf = process(f'qemu-i386 -d exec,nochain -- {working} 2>&1 | wc -l', shell=True)
            # print(b"".join(guess))
            # perf.sendline(b"".join(guess))
            # num_instrs = int(perf.recvall().strip())

            perf = process(["/DynamoRIO-Linux-10.90.19845/bin32/drrun", "-c", "/DynamoRIO-Linux-10.90.19845/samples/bin32/libinscount.so", "--", str(working)])
            perf.sendline(b"".join(guess))
            perf.recvuntil(b"Instrumentation results: ")
            num_instrs = int(perf.recvuntil(b" "))
            perf.close()

            # perf = process(['perf', 'stat', '-e', 'instructions:u', str(working)])
            # perf.sendline(b''.join(guess))
            # perf_line = perf.recvline_contains(b'instructions')
            # print(perf_line)
            # num_instrs = int(perf_line.strip().split()[0].replace(b',', b''))
            # perf.close()

            if num_instrs > best_guess[1]:
                best_guess = (i.encode(), num_instrs)
        known.append(best_guess[0])
        print("known:", known)

    r.sendline(b''.join(known))
    print(r.recvline())

r.sendline(b"./submitter")
print(r.recvuntil(b"Flag: ").decode(), end='')
print(r.recvuntil(b"\n").decode(), end='')
