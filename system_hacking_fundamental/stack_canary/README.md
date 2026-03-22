# 🧠 Concept: Stack Canary <br>
<br>

## 📌 Definition <br>
함수의 프롤로그에서 Stack Buffer와 Return Adress 사이에 임의의 값을 삽입하고, 함수의 에필로그에서 해당 값의 변조를 확인하는 보호기법 <br>
Canary값의 변조가 확인되면 프로세스 강제 종료 <br>
Return Adress를 덮으려면 반드시 Canary를 먼저 덮어야 하므로 Canary 값을 모르는 공격자는 이 값을 변조 <br>


### 📄 Canary Analysis <br>
```c
// Name: canary.c

#include <unistd.h>

int main() {
  char buf[8];
  read(0, buf, 32);
  return 0;
}
```

```
$ gcc -o canary canary.c
$ ./canary
HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH
*** stack smashing detected ***: <unknown> terminated
Aborted
```
Canary를 적용하여 컴파일하고 긴 입력을 주면 기존의 Segmentation fault가 아닌 stack smashing detected와 Aborted error가 발생 <br>
이는 Stack Buffer Overflow를 탐지하고 프로세스가 강제 종료되었음을 의미

```
   push   rbp
   mov    rbp,rsp
   sub    rsp,0x10
+  mov    rax,QWORD PTR fs:0x28
+  mov    QWORD PTR [rbp-0x8],rax
+  xor    eax,eax
+  lea    rax,[rbp-0x10]
-  lea    rax,[rbp-0x8]
   mov    edx,0x20
   mov    rsi,rax
   mov    edi,0x0
   call   read@plt
   mov    eax,0x0
+  mov    rcx,QWORD PTR [rbp-0x8]
+  xor    rcx,QWORD PTR fs:0x28
+  je     0x6f0 <main+70>
+  call   __stack_chk_fail@plt
   leave
   ret
```
추가된 프롤로그의 코드에 중단점 설정하고 실행<br>

```
$ gdb -q ./canary
pwndbg> break *main+8
Breakpoint 1 at 0x6b2
pwndbg> run
 ► 0x5555555546b2 <main+8>     mov    rax, qword ptr fs:[0x28] <0x5555555546aa>
   0x5555555546bb <main+17>    mov    qword ptr [rbp - 8], rax
   0x5555555546bf <main+21>    xor    eax, eax
```
main+8에서 fs:0x28의 데이터를 rax에 저장 <br>
fs는 세그먼트 레지스터의 일종으로 리눅스에서 프로세스가 시작될 때 랜덤 값을 저장 <br>
ni로 실행시, 첫 바이트가 null인 8byte 데이터가 저장되어 있음 <br>
생성한 랜덤값은 main+17에서 rbp-0x8에 저장 <br>

```
pwndbg> break *main+50
pwndbg> continue
HHHHHHHHHHHHHHHH
Breakpoint 2, 0x00000000004005c8 in main ()
 ► 0x5555555546dc <main+50>    mov    rcx, qword ptr [rbp - 8] <0x7ffff7af4191>
   0x5555555546e0 <main+54>    xor    rcx, qword ptr fs:[0x28]
   0x5555555546e9 <main+63>    je     main+70 <main+70>
    ↓
   0x5555555546f0 <main+70>    leave
   0x5555555546f1 <main+71>    ret
```
main+50은 rbp-8에 저장한 canary를 rcx로 옮기고 main+54에서 xor로 비교 <br>
-> 두 값이 동일하면 정상 반환, 다른 경우 __stack__chk_fail 호출되며 프로그램 강제 종료 <br>


### 📄 Canary Generation Process <br>
Carnary 값은 프로세스가 시작될 때, TLS에 전역변수로 저장되고, 각 함수마다 프롤로그와 에필로그에서 이 값을 참조 <br>

