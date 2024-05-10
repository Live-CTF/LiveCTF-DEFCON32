import sys

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def vadd(arr, b):
    return [(x + b) & 0xff for x in arr]

def get_buf():
    buf = [0] * 1000
    ctr1 = 0
    ctr2 = 0
    bounces = 0
    initial_offset = 1

    buf[4] = initial_offset
    buf[5] = 0

    buf[6] = 0x2c
    buf[7] = 0xe0
    buf[8] = 0xe0
    buf[9] = 0x2c

    ctr2_inc = 0
    buf[10:20] = [0x80, 0xff, 0xff, 0xff, 0xff, 0x01, 0x00, 0x00, 0x00, ctr2_inc]   # gravity bonus
    ctr1 += 4
    ctr2 += ctr2_inc
    bounces += 1

    offset = (initial_offset + bounces + ctr1 * ctr2) % 64 * 10
    assert offset == 20

    ctr2_inc = 0
    arr = [0x40, ctr2_inc, 0x00, 0x00, 0x31, 0x33, 0x33, 0x37, 0x7f, 0x7f]
    for j in range(6):
        s_leq = (arr[j + 4] <= 0x2f) or (arr[j + 4] >= 0x80)
        if s_leq or (not s_leq and arr[j + 4] > 0x39 and arr[j + 4] < 0x80):
            ctr1 += 1
    buf[20:30] = vadd(arr, bounces)
    ctr2 += ctr2_inc
    bounces += 1

    offset = (initial_offset + bounces + ctr1 * ctr2) % 64 * 10
    assert offset == 30

    ctr2_inc = 0
    arr = [0x10, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, ctr2_inc, 0x00]
    buf[30:40] = vadd(arr, bounces)
    bounces += 1

    offset = (initial_offset + bounces + ctr1 * ctr2) % 64 * 10
    assert offset == 40

    ctr2_inc = 0
    arr = [0x04, 0x66, 0x55, 0x7a, 0x5a, ctr2_inc, 0x74, 0x48, 0x69, 0x53]
    buf[40:50] = vadd(arr, bounces)
    bounces += 1
    return bytes(buf)

if __name__ == '__main__':
    sys.stdout.buffer.write(get_buf())
