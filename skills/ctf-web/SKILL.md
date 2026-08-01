---
name: ctf-web
description: 二级总纲：CTF Web 工作流 + 三级 leaf 路由表 + 跨切面纪律。触发词：CTF-Web、CTF Web 题、Web CTF。与 auto-pentest 渗透模式并列，不互调流程。
---

# CTF Web 解题工作流（二级 router）

> **定位**：CTF 模式下的 Web 方向。主 agent 统筹调度，**vulnclaw 作为自动化渗透子 agent 承担通用黑盒**（侦察/扫描/深挖），**主 agent 承担 CTF 特化**（flag 定位/提取/总结）。本文件只给工作流骨架 + 漏洞类型路由 + 跨切面纪律；**每漏洞的 payload/工具细节全部下沉到三级 leaf**，不在本文件翻。

> **CTF vs 渗透**：并列两种模式，不互调流程，vulnclaw 被两者共享调用。CTF 拿 flag 即止、不为评估而评估；写解题思路链、不写修复建议；**谨慎提权、默认不提权**；严格区分"已确认"与"推测"，不臆想。

## 三级 leaf 路由表

识别到该考点就调对应 leaf，**不在本文件翻细节**：

| 识别特征 | 调用 leaf |
|---|---|
| SQL注入 / SQL injection / 参数加单引号报错 | `ctf-web-sqli` |
| 反序列化 / deserialize / unserialize | `ctf-web-deser` |
| SSRF / server-side request forgery / 回显URL内容 | `ctf-web-ssrf` |
| 文件上传 / file upload / MIME伪造 | `ctf-web-upload` |
| LFI / RFI / 本地文件包含 | `ctf-web-lfi` |
| 命令注入 / command injection / OS命令执行 | `ctf-web-cmdi` |
| SSTI / 模板注入 / template injection | `ctf-web-ssti` |
| XXE / XML外部实体 / <!ENTITY | `ctf-web-xxe` |
| JWT / JSON Web Token / eyJ | `ctf-web-jwt` |
| SAML / SSO / XSW | `ctf-web-auth-saml` |
| 条件竞争 / TOCTOC / 并发请求 | `ctf-web-race` |
| XSS / 跨站脚本 / `<script>alert` | `ctf-web-xss` |

## 阶段 0：就绪自检

| 依赖 | 自检命令 | 当前状态 |
|---|---|---|
| vulnclaw | `vulnclaw doctor` | ✅ 0.2.9 |
| Burp(9876) | `curl -s -m3 -o/dev/null -w '%{http_code}' http://127.0.0.1:9876/` -> 200 | ✅ 需 Burp 本体运行 |
| Chrome(9222) | `curl -s -m3 http://127.0.0.1:9222/json/version` | ✅ 需调试 Chrome 运行 |
| chrome-devtools MCP | `vulnclaw doctor` 看 attach | ⚠️ npx 形式 attach_failed -> 降级 curl |
| js-reverse MCP | `vulnclaw doctor` 看 attach | ⚠️ 同上 -> 降级 curl+grep |
| fetch MCP | `vulnclaw doctor` | ✅ |
| sqlmap / dirsearch | `which sqlmap dirsearch` | ✅ |
| venv(python) | `/home/threed/ctf/venv/bin/python -c "import Crypto"` | ✅ pycryptodome |

> **WSL2 跨界**：Burp/Chrome 跑在 Windows 侧，vulnclaw 在 WSL2 侧，经 localhost forwarding 用 `127.0.0.1` 访问。Chrome 调试实例（Windows PowerShell，先关所有 Chrome）：`& "C:\Program Files\Google\Chrome\Application\chrome.exe" --remote-debugging-port=9222 --user-data-dir=C:\tmp\chrome-debug`

## 工具降级表

| 能力 | 首选 | 降级（首选不可用时） |
|---|---|---|
| 浏览器渲染/截图 | chrome-devtools `browser_snapshot` | `curl -s <url>` 拉源码 + grep |
| JS 接口提取 | js-reverse `extract_endpoints` | `curl -s <js_url>` + `grep -oE '"/[a-zA-Z0-9/_-]+"'` |
| HTTP 请求/重放 | burp `send_http1` / `create_repeater_tab` | `curl` / fetch MCP |
| 浏览器执行 JS | playwright `browser_evaluate` | 手工分析 + curl 构造请求 |

## 工作流阶段骨架

### 阶段 1：侦察（委派 vulnclaw + 流量）
1. **`vulnclaw recon <TARGET>`** - 端口/服务/目录/指纹（单端口靶机加 `--only-port <端口>`）
2. **`burp get_proxy_http_history`** - 记录所有 HTTP 交互
3. **JS 审计** - js-reverse `extract_endpoints`（降级：`curl` 拉 .js + grep 找端点/密钥）
4. **页面源码** - chrome-devtools `browser_snapshot`（降级：`curl`）+ 搜注释提示
5. 收集所有 .php 入口；**若给源码** -> 进阶段 4 白盒审计

### 阶段 2：扫描（委派 vulnclaw + 敏感文件）
1. **`vulnclaw scan <TARGET>`** - Nuclei + CMS 模板
2. **敏感文件** - `/.git/`、`/.env`、`/config.php.bak`、`/robots.txt`、`/.svn/`（curl/dirsearch）
3. **管理面板** - `/admin`、`/login`、`/manage`（500 也可能存在，尝试访问/登录）
4. **sqlmap** - 对疑似注入点 `sqlmap -u <URL> --batch`

### 阶段 3：专项利用（识别 → 路由 → 调 leaf）

**识别漏洞类型 → 查上方"三级 leaf 路由表" → 调对应 `ctf-web-*` leaf，不在本文件堆 payload。** 各漏洞的探测 payload、绕过技巧、利用链全在 leaf 内。通用 CTF 动作（非某类漏洞专属）：批量读源码找后门/硬编码凭据/flag 展示逻辑、凭据利用链（源码/LFI 拿凭据 -> DB dump -> 后台登录）、PoC 用 burp `send_http1`/`create_repeater_tab`（降级 curl）。

### 阶段 4：白盒审计（若有源码）
CTF 常给源码，auto-pentest 全黑盒无此阶段：
1. 定位入口文件/路由
2. 危险函数：`eval/system/exec/passthru/unserialize/include/open`
3. 框架版本已知漏洞
4. 审计结果指向阶段 3（查路由表调 leaf）

### 阶段 5：flag 提取与校验
**flag 定位（按优先级试，逐项记录"确认/未找到"）**：
1. RCE 后直接读：`cat /flag`、`/flag.txt`、`env`、`find / -name 'flag*' 2>/dev/null`
2. 读后台源码找 flag 展示逻辑（php://filter 读 `admin/index.php` 等）
3. 数据库查 flag 表；4. 文件包含读 flag
5. **确认 flag 存在但不可读**（`stat` 确认存在 + `cat` 报 Permission denied）-> 进"提权策略"
6. **flag 格式校验**：`flag\{[^}]+\}` 或题目指定格式

> ⚠️ 严禁臆想：区分"已确认 flag 在 X"与"推测 flag 可能在 X"，无依据不写结论。

## 提权策略（谨慎）

CTF Web 题默认**不提权**——flag 通常通过 Web 漏洞(RCE/后台/数据库)即可获取。仅当**确认** flag 存在但当前权限不可读时才尝试，且：
1. 必须有证据（`stat /flag` 显示存在 + `cat` 报 Permission denied），不靠推测
2. 尝试常规向量：`sudo -l`、SUID(`find / -perm -4000`)、内核版本对应漏洞、docker socket——**失败即停，不无限深挖**
3. 提权题一般属 pwn/专项方向，Web 链路已尽且需复杂提权时标注"需提权，建议转专项"而非硬磕
4. 报告中明确标注"已确认/尝试未果/推测"

## 阶段 6：总结报告（每题必写）

> **AK 模式**（见 ctf-master）：跳过本阶段，拿到 flag 立即返回 `flag + 一句话解法 + 关键 payload`，报告后置到 Phase 3。

每题产出总结报告 `/home/threed/ctf/web/solve_{题目名}.md`，借鉴渗透报告结构、CTF 适配（目标概况 / 漏洞清单分级 / 攻击路径ASCII图 / 获取的权限与数据 / flag状态 / 解题思路链替代修复建议 / 工具链使用记录）。flag 同步追加到 `/home/threed/ctf/web/flags.txt`，流量可导出 Burp project。

## vulnclaw 调用纪律

- `recon`/`scan`：`vulnclaw recon <TARGET>`、`vulnclaw scan <TARGET>`（TARGET 可带端口，如 `8.148.64.22:10000`）；单端口靶机加 `--only-port <端口>`
- **`--scope` 只有 `run` 子命令有**，recon/scan 无此选项（实测 `vulnclaw recon --scope web` 报错）
- **委派深度**：可委派 `vulnclaw run <TARGET> --scope web` 做深度 Web 渗透，主 agent 接管 flag 定位与提取。vulnclaw 是渗透思维，产出按 CTF 目标过滤（只要 flag 相关，忽略修复建议/横移）
- recon/scan 本身不后渗透，无需 `--block-actions`；委派后读产出（`./vulnclaw-output/` 或 `--output`），不手把手指导每步；`--resume` / `--snapshot` 可续跑

## 跨切面纪律

1. **平台域名直连**：adworld/xctf 平台 "http IP PORT" 格式对应域名 `oj-IP-PORT.adworld.xctf.org.cn`（IP 的点替换为连字符）。题目给 "http 10.30.15.1 38295" -> 直接用 `http://oj-10-30-15-1-38295.adworld.xctf.org.cn/`，**别先 probe 原始 IP**（内网地址公网不通会超时，浪费往返且要等用户打断补域名）。
2. **多步 HTTP 用 Python requests，别用 curl cookie jar**：注册->登录->SSO->ACS 这类带 session 状态的链路，curl `-c/-b` cookie jar 不可靠（跨请求/host 丢 cookie），易出假阴性。直接写 requests 脚本。
3. **exploit 零依赖优先**：用标准库 `urllib` + 字符串操作构造 payload，避免 lxml/requests 等需安装的依赖——装包易被网络/沙箱阻断（pip 源超时、classifier 临时不可用）。
4. **测试优先于推理**：nameID 取 email 还是 username、服务是否注册、type 能否存 0 等可实证问题，**先测一次再下结论**，别长篇推理。
5. **验证限时（只做一次）**：拿到 flag 后做**一次**对比验证（如 XSW 注入不同 nameid 看 403 vs flag）证明非假阳性即可；**不要**再做本地全栈复现（docker 拉镜像慢/网络易失败），除非远程对比无法判定。
6. **硬编码凭据先试**：审到 `docker-compose.yml`/`add-admin.js`/环境变量里的默认 admin 密码（如 `ADMIN_PASSWORD`）时，先直接登录试最短路径，再展开广度侦察。
7. **环境致命错：跳过 + 留 watcher，别判死**（见 [[feedback-infra-down-not-unsolvable]]）：靶机返回 `Class 'mysqli' not found`、PHP 5.6 解析 PHP7+ 语法（`??`）失败等 fatal 时，是**实例/镜像 transient 故障**，不是题目永久无解。正确姿势：(a) 区分 `this instance is broken right now` vs `challenge is unsolvable`，只承认前者；(b) **跳过的同时挂低成本后台 watcher**（Monitor/循环脚本，几分钟一次）自动重试 exploit，实例一活即出 flag；(c) reset 一次仍坏 = 平台还在迭代镜像，watcher 继续跑，窗口 30–60 min；(d) 优先验证 exploit 是否 DB/环境无关（核心 trick 如 `union/**/select` + 序列化 SSRF 常常 DB 无关），修好后零改动复用。

## 输出规则

| 规则 | 路径 |
|---|---|
| 总结报告 | `/home/threed/ctf/web/solve_{题目名}.md` |
| flag | `/home/threed/ctf/web/flags.txt` |
| vulnclaw 产出 | 运行时 cwd 的 `./vulnclaw-output/` 或 `--output` 指定 |

## 使用方式

输入："帮我做这道 CTF Web 题: http://target:port/"
或："这个登录框有 SQL 注入，帮我验证拿 flag"
触发后按阶段 0 -> 6 执行，**每题必出总结报告**（AK 模式除外）。
