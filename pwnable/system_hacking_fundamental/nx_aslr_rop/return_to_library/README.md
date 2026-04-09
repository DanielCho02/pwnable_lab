# ☘️ Return to Library

# 🎯 Goal
**RTL: NX(No eXecute)를 우회하는 공격 기법**

```c
// Name: rtl.c
// Compile: gcc -o rtl rtl.c -fno-PIE -no-pie

#include <stdio.h>
#include <stdlib.h>

const char* binsh = "/bin/sh";

int main() {
  char buf[0x30];

  setvbuf(stdin, 0, _IONBF, 0);
  setvbuf(stdout, 0, _IONBF, 0);

  // Add system function to plt's entry
  system("echo 'system@plt'");

  // Leak canary
  printf("[1] Leak Canary\n");
  printf("Buf: ");
  read(0, buf, 0x100);
  printf("Buf: %s\n", buf);

  // Overwrite return address
  printf("[2] Overwrite return address\n");
  printf("Buf: ");
  read(0, buf, 0x100);

  return 0;
}
```

### 📄 Code Analysis
1. "/bin/sh" ASLR이 적용되도 PIE가 적용되지 않으면 CODE와 DATA segment의 주소는 고정됨.
2. **Return to PLT: PLT의 주소 또한 고정, 라이브러리의 베이스 주소를 몰라도 라이브러리 함수를 실행할 수 있는 공격기법**   
   cf. PLT = GOT 라이브러리 함수의 참조를 위해 사용되는 테이블


### 🗡️ Exploit
1. Canary 우회
2. system("/bin/sh")을 호출하면 셸 획득 가능

**Return gadget: ret 명령어로 끝나는 어셈블리 코드 조각**

```bash
$ ROPgadget --binary ./rtl --re "pop rdi"
Gadgets information
============================================================
0x0000000000400853 : pop rdi ; ret
```

```bash
pwndbg> search /bin/sh
rtl             0x400874 0x68732f6e69622f /* '/bin/sh' */
rtl             0x600874 0x68732f6e69622f /* '/bin/sh' */
libc-2.27.so    0x7ff36c1aa0fa 0x68732f6e69622f /* '/bin/sh' */
```

### ✅ Conclusion
pop rdi의 주소를 구하고자 했는데 없어서 인터넷과 chatGPT의 힘을 빌렸다.    
같은 `rtl.c`라도 다시 컴파일하면 가젯 주소, PLT 주소, 문자열 주소가 달라질 수 있다.  
따라서 pwnable 문제를 풀 때는 **문제에서 제공된 원본 ELF를 그대로 사용해야 하며, 직접 컴파일한 바이너리를 기준으로 exploit을 작성하면 안 된다.**   

ROP는 ret으로 함수처럼 실행 흐름을 이어붙이는 것이다
ret = stack에서 주소 꺼내서 jump   

ret : 실행 흐름 맞추기   
 ↓    
pop rdi ; ret : 인자 넣기, gadget 실행    
 ↓   
rdi = "/bin/sh"   
 ↓    
system("/bin/sh") : 실행   
즉, 문자열 "/bin/sh" 자체를 넣는 것이 아니라,     
그 문자열이 저장된 메모리 주소를 rdi에 넣은 뒤 system을 호출             
 




