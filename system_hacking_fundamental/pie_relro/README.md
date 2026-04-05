# 🧠 PIE(Position-Independent Executable)

## 📌 Definition
ASLR(Address Space Layout Randomization) 적용 시 바이너리가 실행될 때마다 stack, heap, shared library 등이 무작위 주소에 매핑
하지만 일반적으로 ASLR이 적용되더라도 실행 파일의 `main()`이나 전역 변수 등이 위치한 주소는 항상 고정된 상태
PIE는 실행 파일이 매핑된 영역에도 적용

```c
// Name: addr.c
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
    char buf_stack[0x10];                   // 스택 영역의 버퍼
    char *buf_heap = (char *)malloc(0x10);  // 힙 영역의 버퍼

    printf("buf_stack addr: %p\n", buf_stack);
    printf("buf_heap addr: %p\n", buf_heap);
    printf("libc_base addr: %p\n",
        *(void **)dlopen("libc.so.6", RTLD_LAZY));  // 라이브러리 영역 주소

    printf("printf addr: %p\n",
        dlsym(dlopen("libc.so.6", RTLD_LAZY),
        "printf"));  // 라이브러리 영역의 함수 주소
    printf("main addr: %p\n", main);  // 코드 영역의 함수 주소
}
```
ASLR과 PIE가 동시에 적용된 경우 스택, 힙, 라이브러리 영역의 주소 뿐만 아니라 main()의 주소도 매번 다르게 출력

## 📄 PIC(Position-Independent Code)
ELF는 실행파일(Executable)과 공유 오브젝트(Shared Object, SO)로 두 가지 존재    
SO는 기본적으로 재배치 가능: 메모리의 어느 주소에 적재되어도 코드의 의미가 훼손되지 않음    
PIC: 재배치 가능한 코드    
코드가 자기 기준점(rip)을 보고 데이터 위치를 계산하니까, 프로그램이 메모리 어디에 올라가도 정상 동작     

## 📄 PIE
PIE: 무작위 주소에 매핑되도 실행 가능한 파일     
리눅스의 실행 파일 형식은 재배치를 고려하지 않고 설계되었기 때문에 원래 재배치가 가능했던 공유 오브젝트를 실행파일로 사용하기로 함    

```bash
$ readelf -h /bin/ls
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              DYN (Position-Independent Executable file)
  Machine:                           Advanced Micro Devices X86-64
  Version:                           0x1
  Entry point address:               0x6ab0
  Start of program headers:          64 (bytes into file)
  Start of section headers:          136224 (bytes into file)
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           56 (bytes)
  Number of program headers:         13
  Size of section headers:           64 (bytes)
  Number of section headers:         31
  Section header string table index: 30
```
실제로 리눅스의 기본 실행 파일 중 하나인 /bin/ls의 파일 헤더를 살펴보면, Type이 공유오브젝트
DYN(ET_DYN)임을 확인할 수 있음   

PIE는 재배치가 가능하므로 ASLR이 적용된 시스템에서는 실행파일도 무작위 주소에 적재    
반대로, ASLR이 적용되지 않은 시스템에서는 PIE가 적용되더라도 무작위 주소에 적재 X    

```bash
$ gcc -o pie addr.c -ldl
```

여러번 실행해보면 main()의 주소가 매번 바뀌고 있음을 확인 가능    

```bash
$ gcc -o pie addr.c -ldl
$ ./pie
buf_stack addr: 0x7ffc85ef37e0
buf_heap addr: 0x55617ffcb260
libc_base addr: 0x7f0989d06000
printf addr: 0x7f0989d6af00
main addr: 0x55617f1297ba
$ ./pie
buf_stack addr: 0x7ffe9088b1c0
buf_heap addr: 0x55e0a6116260
libc_base addr: 0x7f9172a7e000
printf addr: 0x7f9172ae2f00
main addr: 0x55e0a564a7ba
$ ./pie
buf_stack addr: 0x7ffec6da1fa0
buf_heap addr: 0x5590e4175260
libc_base addr: 0x7fdea61f2000
printf addr: 0x7fdea6256f00
main addr: 0x5590e1faf7ba
```

## 🗡️ PIE 우회   
1. 코드 베이스 구하기   
   -  ASLR환경에서 PIE가 적용된 바이너리는 실행될 따마다 다른 주소에 적재
   -  코드 영역의 가젯을 사용하거나 데이터 영역에 접근하려면 바이너리가 적재된 주소를 알아야함
   -  libc_base 주소와 같이 코드 영역의 임의 주소를 leak offset을 빼기   

2. Partial Overwirte   
   - 코드 영역의 주소도 하위 12비트 값은 항상 같음
   - 사용하려는 코드 가젯의 주소가 반환 주소와 하위 한 바이트만 다르다면 이 값만 덮어서 원하는 코드 실행 가능
   - 두 바이트 이상 다른 주소로 실행 흐름을 옮기려면 브루트 포싱이 필요, 확률적 공격 성공

