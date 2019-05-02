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
