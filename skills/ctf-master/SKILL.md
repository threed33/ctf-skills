---
name: ctf-master
description: CTF 总控调度 skill。接收题目 -> 判断赛道 -> 分发到 Web/Crypto/Misc 子 skill -> 汇总 flag 与解题报告。触发词：CTF、解题、比赛、flag、签到、ak、全杀、速通、冲榜。与 auto-pentest 并列，共享 vulnclaw。AK 模式下报告后置、flag 优先级最高（见“AK 竞赛模式”节）。
---

# CTF 总控调度

> **与 auto-pentest 并列的第二种模式**：auto-pentest 面向授权渗透（找漏洞、写修复、链路深挖）；ctf-master 面向比赛解题（拿 flag 即止、不写修复、提权谨慎不臆测）。两者**共享 vulnclaw** 作为自动化执行引擎，但目录隔离、目标不同、报告不同。
> **硬约束：仅在授权靶机/比赛环境操作；提权需证据、失败即停、不臆测 flag 位置；暂只做 web/crypto/misc，其他赛道直接说明并跳过。**

## 三级技能树（架构）

本流程已三级化——知识按考点拆成 leaf，总纲不再堆细节，避免单 skill 随解题增多而冗长杂乱：

- **一级 · 本文件（ctf-master）**：调度 + 判断赛道 + 全局纪律（AK 模式 / infra-down / flag 优先）。
- **二级 · 方向总纲**：`ctf-web` / `ctf-crypto` / `ctf-misc`。只给**工作流骨架 + 三级 leaf 路由表 + 跨切面纪律**，不含每漏洞 payload。
- **三级 · 知识 leaf（以考点本身为锚点，按需调用）**：

| 方向 | leaf（碰到该考点就调） |
|---|---|
| web | `ctf-web-sqli` `ctf-web-deser` `ctf-web-ssrf` `ctf-web-upload` `ctf-web-lfi` `ctf-web-cmdi` `ctf-web-ssti` `ctf-web-xxe` `ctf-web-jwt` `ctf-web-auth-saml` `ctf-web-race` `ctf-web-xss` |
| crypto | `ctf-crypto-encoding` `ctf-crypto-classical` `ctf-crypto-rsa` `ctf-crypto-hash` `ctf-crypto-symmetric` `ctf-crypto-whitebox` |
| misc | `ctf-misc-stego` `ctf-misc-forensics` `ctf-misc-puzzle` |

**调度链**：`ctf-master`（判赛道）→ 二级 `ctf-<track>`（工作流 + 按识别特征查路由表）→ 三级 `ctf-<track>-<vuln>`（该考点怎么打：payload / 决策树 / 实战结晶）。
**调用机制**：三级 leaf 的 `description` 写满该考点指纹词，做题时按需命中加载；二级路由表是显式分发兜底。leaf 间用 markdown 链接互引（如 Fakebook 链 `ctf-web-sqli`→`ctf-web-deser`→`ctf-web-ssrf`）。
**知识增长纪律**：新解题经验写进对应**叶子**（不进总纲）；总纲只在新增考点或跨切面纪律变化时动。每个 ★ leaf 已结晶本次比赛真题数据（Fakebook / php文件上传 / file-upload-lfi / rsa / pairing / 编码 / 凯撒）。
**四级深叶子（按需下钻）**：当某个三级 leaf 内出现**独立且足够深**的知识子域（自己的算法 + 实例 + 教训），再下钻一级，由该 leaf 的决策表路由。当前仅 `ctf-crypto-rsa-related-message`（限时 resultant，`ctf-crypto-rsa` 决策树下钻）——别对一两行命令的小攻击（Wiener/Fermat 等）过度碎片化，那会降效。

## 两种模式对照

| 维度 | auto-pentest（渗透模式） | ctf-master（CTF 模式） |
|------|------|------|
| 目标 | 摸清资产、找全漏洞、拿权限 | 拿 flag，拿到即止 |
| vulnclaw | 主控，全流程驱动 | 仅 Web 赛道委派侦察/扫描；crypto/misc 不用 |
| 深度 | 攻击链 + 后渗透 + 修复建议 | 最短拿 flag 路径，不写修复 |
| 提权 | 容器内探测 | 谨慎，需证据，失败即停，不臆测 |
| 报告 | 渗透报告（漏洞清单+修复建议） | 解题报告（攻击链+flag，无修复） |
| 目录 | `/home/threed/pentest/` | `/home/threed/ctf/` |
| 赛道 | 不分 | web / crypto / misc 三选一 |

## 赛道判断规则

| 特征 | 赛道 | 委派 skill |
|------|------|------|
| 有 URL / IP:端口 / HTTP 服务 / Web 源码 | **Web** | `ctf-web` |
| 含 n/e/c/p/q/d 参数、RSA/AES/密码学描述、`.pem`/`.key`/密文文件 | **Crypto** | `ctf-crypto` |
| 附件是图片/音频/pcap/磁盘镜像/未知文件、隐写取证描述 | **Misc** | `ctf-misc` |
| 不确定 | 先 `file` 识别附件类型 + 读题干关键词，再分发；仍判不准先按 misc 探文件类型 | — |

> **不在 web/crypto/misc 范围的题（pwn / 逆向 / blockchain / mobile）**：本流程暂不覆盖，直接说明"超出当前 CTF 流程支持范围"并跳过，不臆造解法。

## 解题调度流程

```
1. 接收题目（描述 + 附件 + URL/端口）
2. 判断赛道（上表）；不确定先 file 识别
3. 委派对应 ctf-* skill 执行
   - Web    : vulnclaw recon/run + 手工利用   → 见 ctf-web
   - Crypto : venv 跑 RsaCtfTool / 自写脚本    → 见 ctf-crypto
   - Misc   : 取证隐写工具链                   → 见 ctf-misc
4. 提取 flag → 校验格式 → 追加 flags.txt
5. 写解题报告 solve_{题目名}.md（各子 skill 自带模板）
6. 更新 scoreboard.md
```

## 多题并发（比赛场景）

- 比赛多题时按赛道分组，可并行委派多个子 skill（web 题一批、crypto 题一批）。
- 每题独立报告，flag 统一汇总到 `/home/threed/ctf/flags.txt`。
- **主 Agent 只做调度、判断、去重、汇总，不亲自堆技术命令**——技术细节委派子 skill / 子 agent 并行跑（见 [[feedback-delegate-heavy-work]]）。

## AK 竞赛模式（全杀速通）

> **触发**：用户说 "ak" / "全杀" / "速通" / "冲榜" / "所有题做完再写报告"。
> **核心反转**：默认流程每题解完即写报告；AK 模式下**报告全部后置**，解题阶段只产 flag + 一句话解法。flag 优先级最高。

### 三阶段

**Phase 0 - 建板（主 agent，2-3 min）**
1. 列全部题：名称 / 赛道 / 分值 / 附件 / 远程目标
2. **并行双扫**（同一批子 agent 同时干两件事，低 effort）：
   - **(a) 搜题解（低成本并行探针，不是主线）**：拿题面指纹（题名、源码常量、附件名）顺手搜一下 GitHub/CTFtime。**定位是"意外之喜"，不是必中**——搜不到/搜很久都正常，别在搜索上耗时间：每题 time-box ~1-2 min，不中就立刻转正常解题、不纠缠。命中才进 Phase 1「复用快通道」。
     - **工具链**：一条命令 `/home/threed/ctf/tools/search_writeup.sh "<题名或特征串>"`（内部走 GitHub repo+code 搜索，已封装、自带 token）；读题解=`curl raw.githubusercontent.com/<o>/<r>/<br>/<f>` 或 `api.github.com/repos/<o>/<r>/contents`；CTFtime=`curl -A 'Mozilla/5.0' ctftime.org/...`；CryptoHack/论坛 URL 贴给主 agent。（本环境 WebSearch/WebFetch/webReader 走 Z.ai 网关配额常挂，弃用。）
   - **(b) 题型侦察**：扫附件，回：题型预判 + 难度（易/中/难）+ 一句话入手点
3. 建看板 `/home/threed/ctf/scoreboard.md`：`题号|题名|赛道|难度|搜到题解?|状态|flag|卡点`
4. **排序拿分**：① **易/中等题是主线，正常清**（主旋律，快速攒分攒思路）；② 搜到现成题解的题（探针命中）插队快速拿，但**不阻塞主线、别熬夜搜**；③ 难题同时启动但低优先（耗时长，早开跑）

**Phase 1 - 并发解题（每题一个子 agent，fan-out）**
- **搜到题解的题走复用快通道**：子 agent 任务 = 把题解 solver/payload 适配到本题远程（改 flag/目标/端点/参数）→ 最小验证 → 拿 flag。**不从零推导**，几分钟一道。
- 其余题子 agent 走对应 ctf-* skill 的 recon->vuln->exploit->flag，但**跳过总结报告阶段**（委派 prompt 里声明 “AK 模式：跳过报告，拿到 flag 立即返回”）
- 子 agent 只回结构化结论：
  - 成功：`flag` + `一句话解法` + `关键 payload/命令`（exploit 落盘备 Phase 3 复盘）
  - 卡住：`卡点` + `已试方法` + `建议下一步`
- 主 agent 收到 flag -> **立即贴上下文（代码块）** -> 追加 flags.txt -> 更新看板 -> 派下一题
- 难题 effort 调高，简题 effort 调低省 token

**Phase 2 - 疏通升级（主 agent 编排）**
- 卡住题：读 blocker，四选一：换思路重派 / 给提示重派 / 上 Workflow 多角度 fan-out / 暂时跳过
- **深挖过载信号**：某题吃掉大量输出/上下文（撞 token 上限、反复长推导）= 在从零硬啃，优先转"搜题解"或先跳过做别的，别钻。
- 单思路时间盒 ~15 min 无进展必换路，不钻牛角尖
- 全部 flag 到手或时间到 -> 进 Phase 3

**Phase 3 - 报告复盘（全部 flag 后，低优先级）**
- 按 scoreboard + 子 agent 笔记 + 落盘 exploit 写各题 `solve_{题名}.md`
- 时间紧则只保 flags.txt + scoreboard，跳过单题报告

### AK 速度铁律

1. **flag 即止**：拿到就停，不过度利用、不深挖。
2. **flag 先贴**：子 agent 一返回 flag，主 agent 下一条回复先贴全文再做别的（见 [[feedback-flag-paste-to-context]]）。
3. **验证极简**：优先直接打远程拿 flag（远程真值无需本地验证）；只有必须先本地验证 exploit 才用自定义数据，且只做一次最小确认（见 [[feedback-local-verify-custom-data]]）。不做对比矩阵、不本地复现整链。
4. **并行优先**：永远并发开题不串行；主 agent 不亲自堆技术命令（见 [[feedback-delegate-heavy-work]]）。
5. **报告后置**：解题阶段零报告产出，只记一句话解法。
6. **卡点时间盒**：单思路 >15 min 无进展即换路或跳过。
7. **先易后难 + 搜题解当低成本探针**：拿分主旋律是易/中等题，先清；搜题解（GitHub/CTFtime，见 [[feedback-check-known-leaked-challenge]]）当**并行低成本探针**——命中即复用、**不命中不纠缠**（搜不到很正常，每题 time-box ~1-2 min，别耗时间）；难题宁搜勿硬啃。

## 环境故障处理（容器致命错，全赛道通用）

子 agent 回报靶机 fatal 级环境错（`Class 'X' not found`、PHP 版本解析失败、列名不匹配、扩展缺失等）时，**这是实例/镜像 transient 故障，不是题目永久不可解**——CTF 平台常轮换/修复实例（每次 reset 端口都变）。主 agent 处理纪律：

1. **区分两个命题**：`this instance is broken right now`（常真，transient）vs `this challenge is unsolvable`（别下）。只承认前者。
2. **「暂时跳过去拿别的分」是正确策略，保留**：比赛时间有限，死磕当前坏的靶机 = 浪费可拿的分（见 [[feedback-ak-mode]]）。要避免的只有两件事——① 把 transient 判成永久结论；② 跳过时不留 revisit。
3. **跳过 + 留尾巴**：跳之前花几乎零成本挂后台 watcher（Monitor / 循环脚本，几分钟一次）自动重试 exploit，并在 scoreboard 标"实例故障/待重试"（不是"不可解"）。watcher 命中即报，无需人工盯。
4. **验环境无关性**：核心 payload 常常 DB/环境无关（如 SQLi 注入序列化串 + SSRF 读文件），实例修好后零改动复用——确认后更可放心先做别的。
5. reset 一次仍坏 = 平台还在迭代镜像，不是永久坏；watcher 继续跑，窗口 30–60 min。

> 实战教训（2026-07-31 TopSecCTF）：Fakebook/胖虎 跳过去做别的题没错，错在下了"永久坏"结论 + 没挂 watcher；Fakebook 48 min 后平台修好（mysqli→SQLite3）时没人捡（见 [[feedback-infra-down-not-unsolvable]]）。

## flag 规范

- 校验格式（常见 `flag{...}` / `FLAG{...}` / `ctf{...}` / 比赛特定前缀）；不符先确认是否真 flag，不急着记。
- **命中即止**，不深挖多余权限。
- 追加到 `/home/threed/ctf/flags.txt`，每行：`题目名 | 赛道 | flag`。

## 全程记录

| 文件 | 内容 |
|------|------|
| `/home/threed/ctf/{赛道}/solve_{题目名}.md` | 单题解题链 + flag（各子 skill 模板） |
| `/home/threed/ctf/flags.txt` | flag 汇总 |
| `/home/threed/ctf/scoreboard.md` | 计分板：题号/题目/赛道/状态/flag/用时 |

## 环境检查（开赛前）

```bash
# Web 工具链
vulnclaw doctor
# Crypto（venv）
/home/threed/ctf/venv/bin/python -m RsaCtfTool --help >/dev/null && echo "RsaCtfTool OK"
/home/threed/ctf/venv/bin/python -c "import sympy,gmpy2,Crypto,requests;print('crypto deps OK')"
# Misc
for t in file binwalk exiftool steghide foremost pngcheck tshark zsteg zbarimg ffmpeg; do command -v $t >/dev/null && echo "OK $t" || echo "MISS $t"; done
/home/threed/ctf/venv/bin/vol -h >/dev/null && echo "volatility3 OK"
# 搜题解链路（WebSearch/WebFetch 走网关配额常挂，默认本机 curl）
echo "GITHUB_TOKEN: ${GITHUB_TOKEN:+set}${GITHUB_TOKEN:-MISSING — 建议设（搜索 10→30 req/min，通用 60→5000/hr）}"
curl -sS -m 10 -A 'Mozilla/5.0' -o /dev/null -w 'api.github.com  %{http_code}\n' https://api.github.com
curl -sS -m 10 -A 'Mozilla/5.0' -o /dev/null -w 'raw.github    %{http_code}\n' https://raw.githubusercontent.com/RsaCtfTool/RsaCtfTool/master/README.md
curl -sS -m 10 -A 'Mozilla/5.0' -o /dev/null -w 'ctftime       %{http_code}\n' https://ctftime.org/writeups/
```

## 依赖安装（赛前一次性，已装则跳过）

```bash
# Crypto venv
/home/threed/ctf/venv/bin/pip install sympy gmpy2 requests pycryptodome cryptography factordb-pycli tqdm six bitarray psutil z3-solver
/home/threed/ctf/venv/bin/pip install --no-deps -e /home/threed/ctf/tools/RsaCtfTool/
# Misc 系统（sudo）
sudo apt install -y steghide foremost pngcheck tshark ruby zbar-tools ffmpeg exiftool binwalk
sudo gem install zsteg
# Web：已有 vulnclaw，无需额外
```

> **避坑**：`zsteg` 是 ruby gem（`gem install zsteg`），不是 pip；RsaCtfTool 用 `--no-deps -e` 注册，避免其 `pyproject.toml` 锁的旧版（`cryptography==39.0.1` 等）降级 venv 已装的新版。

## CTF 原则（区别于渗透）

1. **拿 flag 即止**：找到 flag 立刻收手，不做多余后渗透。
2. **不写修复建议**：解题报告只写攻击链和 flag，不写怎么修。
3. **提权谨慎**：只在 flag 明确需要提权才尝试；需有证据支撑路径；失败即停；**不臆测 flag 位置**（如无证据不猜 `/flag`、`/root/flag.txt`）。
4. **区分确认与推测**：报告中明确标注哪些是已验证、哪些是推测。
5. **委派纪律**：主 Agent 只调度判断，技术执行委派子 skill / 子 agent。

## 使用方式

输入:
- "这是 CTF 题目: [描述/附件/URL]" → 自动判赛道并解题
- "比赛开始了，帮我过一遍所有 Web 题" → 批量委派 ctf-web
- "总结当前所有 flag" → 汇总 flags.txt + scoreboard
- "8.148.64.22:10000 这题帮我看看" → 判为 Web，委派 ctf-web
