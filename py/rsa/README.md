- ./key: 是存储生成的key文件，  
- ./pyasn1 是库，  
- ./rsa 是库，  
- rsa_gen.py 是用来生成rsa 2048的key，同时生成了rsa key.c,可以用于c语言计算，采用了自己的算法，并没有采用库函数  
- rsa_encode.py 是用来读取rsa_gen.py生成的key文件，然后用来加密解密签名验签，用来进行验证的，输入以下命令  
: python rsa_encode.py -k3 test.txt  
: python rsa_encode.py -h  查看帮助信息  
- rsa_suc.py  是Crypto的库函数生成的rsa key 文件  
- rsa_t2.py 是采用另一种方法，自行计算并生成rsa的key，但是，生成的是数字，并不是大家常用的压缩后的字符，需要进行进一步处理。
- tst.txt 是用来给rsa_encode.py 进行文件的签名验签的作用的

