# CTF Skill 树架构（v2 三级化 + 四级深叶子）

> **本文件是 CTF 解题 skill 系统的长期架构参考**：记录 v2 三级化迭代的结果、调用机制、知识增长纪律、两系统同步状态，以及以后怎么维护（加 leaf、决定拆几级）。
> **不是某场比赛的产物**——这场能力迭代源于 2026-07-31 TopSecCTF 赛后复盘（见 `topsecctf/RETROSPECTIVE.md`），但 skill 树是系统级资产，持续演进。
> 建立日期：2026-08-01。canonical 源：git 仓库 `~/projects/ctf-skills/`（[github.com/threed33/ctf-skills](https://github.com/threed33/ctf-skills)，public）；`~/.claude/skills/ctf-*` 与 `~/.reasonix/skills/ctf-*` 均为指向仓库的 symlink（v2.2 仓库化）。

---

## 1. 背景与动机

v1 是平坦两级的：`ctf-master` → `ctf-web`/`ctf-crypto`/`ctf-misc`，每道题的细节知识（payload、绕过技巧、实战结晶）直接写进对应方向总纲。问题：**随解题增多，单个总纲 skill 冗长杂乱**——ctf-web 涨到 198 行，混了工作流 + 考点速查表 + SAML 速查 + 专项 payload + 避坑经验，再攒几道题就不可维护。

skill 本质是一个 md 文件，不该把所有知识塞进一个 skill。**v2 把知识按考点本身拆成 leaf**，做题时按知识点精准调对应叶子，而非翻一长串总纲。

## 2. 架构总览（三级 + 按需四级）

```
一级  ctf-master              调度 + 判赛道 + 全局纪律（AK 模式 / infra-down / flag 优先 / 三级树说明）
       │ 判断赛道
       ▼
二级  ctf-web   ctf-crypto   ctf-misc        ← 方向总纲（router）：工作流骨架 + 三级 leaf 路由表 + 跨切面纪律
       │ 路由表（识别特征 → leaf）            ← 已瘦身：web 198→134 / crypto 136→87 / misc 102→89 行
       ▼
三级  21 个知识 leaf（ctf-<track>-<vuln>，扁平顶层、/skill 可直调）
       │ 决策树命中"独立且足够深"的子域时
       ▼
四级  ctf-crypto-rsa-related-message（当前唯一）   ← 深叶子：自己的算法 + 实例 + 教训
```

**分层职责判据**：
- 「**某漏洞/考点怎么打**」→ 三级 leaf（payload / 决策树 / 实战结晶）。
- 「**做题怎么做**」（工作流、工具降级、验证纪律、infra-down）→ 留一/二级总纲。
- 「**某子域深到独立成学**」（自己的算法 + 实例 + 教训）→ 四级深叶子。

## 3. 调用机制（三层保险，loader-agnostic）

1. **description 触发**（主）：每个 leaf 的 frontmatter `description` 写满该考点的中英文指纹词（如 SQL注入/union select/盲注/WAF绕过…），做题时按需被命中加载。**这是"碰到知识点就调对应 skill"的核心**。
2. **二级路由表**（兜底）：ctf-web/crypto/misc 顶部有「识别特征 → leaf」表，显式分发。
3. **leaf 间互引**：用 markdown 链接标常见链路（如 Fakebook 链 `ctf-web-sqli → ctf-web-deser → ctf-web-ssrf`），多考点串联时顺着调。

## 4. 完整 leaf 清单（22 个）

★ = 已结晶真实比赛数据（题名 + 确切 payload + 链路）；薄 = 脚手架（待积累）。

### Web（12）
| leaf | 考点 | 实战结晶 |
|---|---|---|
| `ctf-web-sqli` ★ | SQL 注入 | Fakebook：`union/**/select` 绕 WAF + SQLite + 盲注 |
| `ctf-web-deser` ★ | 反序列化 | Fakebook：SQLi 注入序列化 UserInfo → unserialize 触发 |
| `ctf-web-ssrf` ★ | SSRF | Fakebook：curl 无 CURLOPT_PROTOCOLS → `file://` 读 flag.php |
| `ctf-web-upload` ★ | 文件上传 | php文件上传：MIME 伪造 + GIF89a 直传 .php → RCE |
| `ctf-web-lfi` ★ | LFI/文件包含 | file-upload-lfi：`php://filter` 读源码 |
| `ctf-web-cmdi` ★ | 命令注入 | file-upload-lfi：ping `%0a` 注入 env 拿 flag |
| `ctf-web-ssti` | SSTI 模板注入 | 薄 |
| `ctf-web-xxe` | XXE | 薄 |
| `ctf-web-jwt` | JWT 伪造 | 薄 |
| `ctf-web-auth-saml` ★ | SAML/SSO | 迁入原 SAML 速查（XSW / 签名范围 / type 混淆） |
| `ctf-web-race` | 条件竞争 | 薄 |
| `ctf-web-xss` | XSS | 薄 |

### Crypto（6 + 1 四级）
| leaf | 考点 | 实战结晶 |
|---|---|---|
| `ctf-crypto-encoding` ★ | 编码/多层解码 | NotOnlyBase / 多次编码：base 套娃递归解码 |
| `ctf-crypto-classical` ★ | 古典密码 | 凯撒：遍历 25 偏移 |
| `ctf-crypto-rsa` ★ | RSA（决策树） | rsa9 低指数 + RSA基础小 n；决策树路由到四级深叶子 |
| `ctf-crypto-rsa-related-message` ★⚡ | **四级**：相关明文/resultant | f,l,ag++：限时 resultant，ZZ 提升 1100s→5s |
| `ctf-crypto-hash` | Hash | 薄 |
| `ctf-crypto-symmetric` | AES/DES 对称 | 薄 |
| `ctf-crypto-whitebox` ★ | 白盒/非标准方案 | pairing re-randomizable 绕 oracle |

### Misc（3）
| leaf | 考点 | 实战结晶 |
|---|---|---|
| `ctf-misc-stego` | 隐写 | 薄 |
| `ctf-misc-forensics` | 取证（pcap/内存/磁盘） | 薄 |
| `ctf-misc-puzzle` | 编码谜题/esolang | 薄 |

⚡ = 四级深叶子。

## 5. 四级深叶子规则（什么时候下钻）

**只当三级 leaf 内某子域满足全部三条才拆四级**：
1. **独立**：是不同的知识锚点（如 resultant 是"多密文多项式消元"，区别于标准 RSA 的"单密文分解/利用小参数"）；
2. **足够深**：有自己的算法 + 实例 + 教训（不是一两行命令）；
3. **决策树可路由**：父 leaf 的决策表能明确指向它。

**当前唯一四级**：`ctf-crypto-rsa-related-message`——限时 resultant 攻击（ZZ 提升 / half-GCD / CRT / Hadamard 界 / 2D 格有理重构），含 flag_land 实例 + 撞时限墙教训 + 3 条 memory。

**反例（不拆）**：Wiener / Fermat / 低指数 / 共模——都是一两行命令，拆成独立 leaf 是**过度碎片化，反而降效**，留在 `ctf-crypto-rsa` 决策树里。

## 6. 知识增长纪律（最重要）

> **以后每解一道题的细节经验，写进对应叶子（不进总纲）；总纲只在新增考点或跨切面纪律变化时动。**

- 新 trick / payload / 实战结晶 → 对应三级 leaf 的「CTF 实战结晶」节。
- 新考点（树里还没有的漏洞类型）→ 新建三级 leaf + 二级路由表加一行。
- 新的跨切面方法论（如新的验证纪律、新的避坑）→ 一/二级总纲。
- 三级 leaf 内某子域长到满足 §5 三条 → 下钻四级。

判据永不变：「某漏洞怎么打」→ leaf；「做题怎么做」→ 总纲。

## 7. 与 hack-skills-main / auto-pentest 的关系

- **hack-skills-main**（102 子技能渗透 playbook 库）：CTF leaf 的**深度参考**——穷尽技巧/WAF 矩阵/真实 CVE 时，leaf 里用 `hack-skills-main/skills/<x>/SKILL.md` 链接指向它。CTF leaf 自包含（拿 flag 即止、不写修复、靶机不出网优先本地回显），hack-skills-main 是补充不是依赖。
- **auto-pentest**：与 ctf-master 并列的第二种模式（渗透 vs 解题），共享 vulnclaw，目录/目标/报告不同。三级 leaf 不被 auto-pentest 调用。

## 8. 仓库化与两系统同步（v2.2，2026-08-01）

skill 树已建成 git 项目仓库作为**唯一 canonical 源**，两个加载路径都是指向它的 symlink——彻底告别手动 cp 同步、永不漂移。

| 角色 | 路径 | 说明 |
|---|---|---|
| **canonical 源（git 仓库）** | `~/projects/ctf-skills/` | 26 ctf skill 真身 + docs + scripts；远程 [github.com/threed33/ctf-skills](https://github.com/threed33/ctf-skills)（public） |
| Claude Code 加载路径 | `~/.claude/skills/ctf-*` | 26 个 symlink → 仓库；`hack-skills-main`/`auto-pentest` 仍是各自真身（非本仓库） |
| reasonix 加载路径 | `~/.reasonix/skills/ctf-*` | 26 个 symlink → 同一仓库源（与 .claude 真正同文件） |

- **单一源**：编辑仓库内 `skills/<x>/SKILL.md`，两个加载路径即时生效。解题时往 skill 写经验直接落进 git。
- **安装到新机器**：`git clone <repo> ~/projects/ctf-skills && bash scripts/install-symlinks.sh`（幂等建两侧 symlink）。
- **校验**：`bash scripts/verify-tree.sh`（26 symlink 有效 + 路由表引用闭合）。
- `hack-skills-main`（102 渗透 playbook，第三方完整项目）与 `auto-pentest` 不纳入仓库，留在 `~/.claude/skills/` 原地；CTF leaf 对 `hack-skills-main/...` 的深度参考链接仍有效。
- memory（`~/.claude/.../memory/` 与 `~/.reasonix/memory/global/`）仍各自维护，本架构决策两边都有 `project-ctf-skilltree-three-level`。

## 9. 演进时间线

- **v1（2026-07 前后）**：平坦两级，知识堆总纲 → 总纲臃肿。
- **v2（2026-07-31）**：三级化重构。workflow 并行编写 21 三级 leaf + 重构 3 二级 router；★ leaf 结晶 TopSecCTF 真题数据。
- **v2.1（2026-08-01）**：RSA 外科手术式拆四级（仅 related-message）；hack-skills-main 推 reasonix；两系统完全对齐。
- **v2.2（2026-08-01）**：仓库化。skill 树建成 git 项目 `threed33/ctf-skills`（public）作唯一 canonical 源；`.claude`/`.reasonix` 两加载路径全部改 symlink 指向仓库，告别 cp 同步。配套 `install-symlinks.sh`/`verify-tree.sh`/`sync-reasonix.sh`。

## 10. 维护指南

**加一个新 leaf**：
1. 确定考点锚点 → 命名 `ctf-<track>-<vuln>`，在仓库建 `~/projects/ctf-skills/skills/<name>/SKILL.md`。
2. 按模板写 SKILL.md（frontmatter description 揉满指纹词 + 识别特征 + 核心手法 + 实战结晶 + 工具命令 + 深度参考 + 关联 leaf）。模板见任一现有 ★ leaf。
3. 二级 router 路由表加一行（识别特征 → 新 leaf）。
4. `bash scripts/install-symlinks.sh`（为新 leaf 在 `.claude`/`.reasonix` 建 symlink）。
5. 若该 leaf 是某父 leaf 的深子域，父 leaf 决策树加下钻指针（参考 `ctf-crypto-rsa` → `ctf-crypto-rsa-related-message`）。
6. `git add -A && git commit && git push`。

**改任意 skill**：直接编辑仓库内 `skills/<x>/SKILL.md`（= 两个加载路径即时生效），`git commit && git push`。**不再 cp 同步。**

**决定拆几级**：默认三级。只有满足 §5 三条（独立 + 足够深 + 决策树可路由）才四级。绝不为一行命令的小攻击拆四级。

**同步 / 校验命令速记**：
```bash
cd ~/projects/ctf-skills
bash scripts/install-symlinks.sh   # 建/修复两侧 symlink（幂等）
bash scripts/verify-tree.sh        # 校验 26 symlink + 路由表闭合
git add -A && git commit -m "..." && git push
```
