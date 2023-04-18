from pwn import *


context.arch = "i386"
context.os = "linux"
print(asm(shellcraft.sh()))
