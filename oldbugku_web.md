# 旧版Bugku-Web
## 题目类型：
|类型|年份|难度|
|:---:|:---:|:---:|
|网上练习题|无|易|

# 题目下载：
+ https://ctf.bugku.com/

# 网上公开WP：
+ https://www.cnblogs.com/Gzu_zb/category/1350848.html
+ https://www.jianshu.com/p/51d976888807

# 本站备份WP:
**作者：淡看**
## Web
### extract变量覆盖

extract函数的实例

![Image.png](https://i.loli.net/2019/05/02/5ccad89a61966.png)

![Image.png](https://i.loli.net/2019/05/02/5ccad6bb9188b.png)

file_get_contens函数，直接读入在一个字符串中
![Image.png](https://i.loli.net/2019/05/02/5ccad688a8c67.png)

给出代码参考
```
<?php
$flag='xxx';
extract($_GET);
if(isset($shiyan))
{
$content=trim(file_get_contents($flag));
if($shiyan==$content)
{
echo'flag{xxx}';
}
else
{
echo'Oh.no';
}
}
?>
```
根据题意
直接使两个值直接相等即可
payload:?shiyan=&flag=
payload:?shiyan=&content=
拿到flag

![a.png](https://i.loli.net/2019/05/02/5ccadb4e7a7df.png)

### strcmp比较字符串

![Image.png](https://i.loli.net/2019/05/02/5ccadb7e2cd41.png)

![Image.png](https://i.loli.net/2019/05/02/5ccadb8d60788.png)

![Image.png](https://i.loli.net/2019/05/02/5ccadb9e7df9c.png)

代码参考
```
<?php
$flag = "flag{xxxxx}";
if (isset($_GET['a'])) {
if (strcmp($_GET['a'], $flag) == 0) //如果 str1 小于 str2 返回 < 0； 如果 str1大于 str2返回 > 0；如果两者相等，返回 0。
//比较两个字符串（区分大小写）
die('Flag: '.$flag);
else
print 'No';
}
?>
```

strcmp直接使用数组绕过
构造payload :?a=[]
即可绕过


### urldecode二次编码绕过
源码

```
<?php
if(eregi("hackerDJ",$_GET[id])) {
echo("not allowed!");
exit();
}
$_GET[id] = urldecode($_GET[id]);
if($_GET[id] == "hackerDJ")
{
echo "Access granted!";
echo "flag";
}
?>
```

eregi匹配字母字符串时忽略大小写

把J对应的url在此进行url加密
%4A->%254A

![Image.png](https://i.loli.net/2019/05/02/5ccadc1d5f43f.png)

这里的二次是因为第一次加密的%4a直接被浏览器给解密了。之后在进行自己的加密变成了%254A。
被php源码解密一次，浏览器解密一次就直接ok了

![Image.png](https://i.loli.net/2019/05/02/5ccadc323939e.png)

得到flag
其他的字母替换均无效
payload:?id=hackerD%254A

### MD5()函数
源码
```
<?php
error_reporting(0);
$flag = 'flag{test}';
if (isset($_GET['username']) and isset($_GET['password'])) {
if ($_GET['username'] == $_GET['password'])
print 'Your password can not be your username.';
else if (md5($_GET['username']) === md5($_GET['password']))
die('Flag: '.$flag);
else
print 'Invalid password';
}
?>
```
想到了md5缺陷的两种利用方法
0e的科学计数法
构造0e payload 尝试绕过
 ?username=s155964671a&password=0e342768416822451524974117254469
无法绕过

![Image.png](https://i.loli.net/2019/05/02/5ccadc6a0d6fc.png)

![Image.png](https://i.loli.net/2019/05/02/5ccadc6a162a4.png)\

使用数组缺陷绕过
构造payload:?username[]=1&password[]=0e
### 数组返回NULL绕过
源码
```
<?php
$flag = "flag";

if (isset ($_GET['password'])) {
if (ereg ("^[a-zA-Z0-9]+$", $_GET['password']) === FALSE)
echo 'You password must be alphanumeric';
else if (strpos ($_GET['password'], '--') !== FALSE)
die('Flag: ' . $flag);
else
echo 'Invalid password';
}
?>
```
ereg和eregi差不多的，区别在于是否匹配大小写
if (ereg ("^[a-zA-Z0-9]+$", $_GET['password']) === FALSE)为了判断是否有输入数字、字母

![Image.png](https://i.loli.net/2019/05/02/5ccadcbf79639.png)

1.数组绕过
    payload:?password[]=@
2.截断
    payload:?password[]=%00
### 弱类型整数大小比较绕过
源码
```
<?php
$temp = $_GET['password'];
is_numeric($temp)?die("no numeric"):NULL;
if($temp>1336){
echo $flag;
?>
```
一眼看出矛盾
给传入的password套上了单引号，为字符串
下面又判断是否为数字，是的话要大于1336才输出flag
这里明显就矛盾了。

尝试数组直接绕过处理
payload:password[]=1

### sha()函数比较绕过
```
<?php
$flag = "flag";
if (isset($_GET['name']) and isset($_GET['password']))
{
var_dump($_GET['name']);
echo "";
var_dump($_GET['password']);
var_dump(sha1($_GET['name']));
var_dump(sha1($_GET['password']));
if ($_GET['name'] == $_GET['password'])
echo 'Your password can not be your name!';
else if (sha1($_GET['name']) === sha1($_GET['password']))
die('Flag: '.$flag);
else
echo 'Invalid password.';
}
else
echo 'Login first!';
?>
```
再次供上代码
sha1再次用数组绕过

payload:?name[]=1&password[]=2

### md5加密相等绕过

利用php的hash缺陷直接绕过

```
<?php
$md51 = md5('QNKCDZO');
$a = @$_GET['a'];
$md52 = @md5($a);
if(isset($a)){
if ($a != 'QNKCDZO' && $md51 == $md52) {
echo "flag{*}";
} else {
echo "false!!!";
}}
else{echo "please input a";}
?>
```
代码如上，构造payload?a=s155964671a
因为在php中科学记数法表示的0e开头的都认为为0
所以直接构造

![Image.png](https://i.loli.net/2019/05/02/5ccac25417099.png)

https://www.cnblogs.com/Primzahl/p/6018158.html
这里扔出一个hash缺陷的列表网站供查看


### 十六进制与数字比较
源码
```
<?php
error_reporting(0);
function noother_says_correct($temp)
{
$flag = 'flag{test}';
$one = ord('1'); //ord — 返回字符的 ASCII 码值
$nine = ord('9'); //ord — 返回字符的 ASCII 码值
$number = '3735929054';
// Check all the input characters!
for ($i = 0; $i < strlen($number); $i++)
{
// Disallow all the digits!
$digit = ord($temp{$i});
if ( ($digit >= $one) && ($digit <= $nine) )
{
// Aha, digit not allowed!
return "flase";
}
}
if($number == $temp)
return $flag;
}
$temp = $_GET['password'];
echo noother_says_correct($temp);
?>
```
传入password转化为temp
之后进行操作

php转码把16进制转化为10进制
3735929054转换成16进制为0xdeadc0de，记得带上0x；
payload:?password=0xdeadc0de

### ereg正则%00绕过
源码
```
<?php
$flag = "xxx";
if (isset ($_GET['password']))
{
if (ereg ("^[a-zA-Z0-9]+$", $_GET['password']) === FALSE)
{
echo 'You password must be alphanumeric';
}
else if (strlen($_GET['password']) < 8 && $_GET['password'] > 9999999)
{
if (strpos ($_GET['password'], '-') !== FALSE) //strpos — 查找字符串首次出现的位置
{
die('Flag: ' . $flag);
}
else
{
echo('- have not been found');
}
}
else
{
echo 'Invalid password';
}
}
?>
```
ereg()的正则限限制了多个数字或者大小写字母
strpos()则是查找'-'
1.数组绕过
    payload:?password[]=1
2.%00截断绕过
    payload:?password=1e9%00*-*
### strpos数组绕过
源码
```
<?php
$flag = "flag";
if (isset ($_GET['ctf'])) {
if (@ereg ("^[1-9]+$", $_GET['ctf']) === FALSE)
echo '必须输入数字才行';
else if (strpos ($_GET['ctf'], '#biubiubiu') !== FALSE)
die('Flag: '.$flag);
else
echo '骚年，继续努力吧啊~';
}
?>
```
题目说了数组绕过，直接构造payload
payload:?ctf[]=1

### 数字验证正则绕过
这题比较难，直接参考别人大佬的
```
<?php
error_reporting(0);
$flag = 'flag{test}';
if ("POST" == $_SERVER['REQUEST_METHOD'])
{
$password = $_POST['password'];
if (0 >= preg_match('/^[[:graph:]]{12,}$/', $password)) //preg_match — 执行一个正则表达式匹配
{
echo 'flag';
exit;
}
while (TRUE)
{
$reg = '/([[:punct:]]+|[[:digit:]]+|[[:upper:]]+|[[:lower:]]+)/';
if (6 > preg_match_all($reg, $password, $arr))
break;
$c = 0;
$ps = array('punct', 'digit', 'upper', 'lower'); //[[:punct:]] 任何标点符号 [[:digit:]] 任何数字 [[:upper:]] 任何大写字母 [[:lower:]] 任何小写字母
foreach ($ps as $pt)
{
if (preg_match("/[[:$pt:]]+/", $password))
$c += 1;
}
if ($c < 3) break;
//>=3，必须包含四种类型三种与三种以上
if ("42" == $password) echo $flag;
else echo 'Wrong password';
exit;
}
}
?>
```
参考：https://foxgrin.github.io/posts/25617/
之后看懂了后，会把自己的思路重现一次的

# 评论区
**请文明评论，禁止广告**
<img src="https://ctfwp.wetolink.com/alu/扇耳光.png" alt="扇耳光.png" class="vemoticon-img">  

---
