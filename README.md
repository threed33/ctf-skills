# CTF Skill 树

> 一套三级化（+ 按需四级）的 CTF 解题 skill 系统：以**考点本身为锚点**组织知识，做题时碰到知识点就精准调用对应叶子，而不是翻一长串总纲。结晶自真实比赛数据。

## 架构

```
一级  ctf-master                 调度 + 判赛道 + 全局纪律（AK 模式 / infra-down / flag 优先）
       │ 判断赛道
       ▼
二级  ctf-web   ctf-crypto   ctf-misc     ← 方向 router：工作流骨架 + 三级 leaf 路由表 + 跨切面纪律
       │ 路由表（识别特征 → leaf）
       ▼
三级  21 个知识 leaf（碰到该考点就调）
       │ 决策树命中“独立且足够深”的子域时
       ▼
四级  ctf-crypto-rsa-related-message（当前唯一）   ← 深叶子：自己的算法 + 实例 + 教训
```

**分层判据**：「某漏洞怎么打」→ 三级 leaf；「做题怎么做」→ 留一/二级总纲；「某子域深到独立成学」→ 四级深叶子。

## Leaf 清单（22）

★ = 已结晶真实比赛数据（题名 + 确切 payload + 链路）。

### Web（12）
`ctf-web-sqli`★ `ctf-web-deser`★ `ctf-web-ssrf`★ `ctf-web-upload`★ `ctf-web-lfi`★ `ctf-web-cmdi`★ `ctf-web-ssti` `ctf-web-xxe` `ctf-web-jwt` `ctf-web-auth-saml`★ `ctf-web-race` `ctf-web-xss`

### Crypto（6 + 1 四级）
`ctf-crypto-encoding`★ `ctf-crypto-classical`★ `ctf-crypto-rsa`★ `ctf-crypto-rsa-related-message`★⚡ `ctf-crypto-hash` `ctf-crypto-symmetric` `ctf-crypto-whitebox`★

### Misc（3）
`ctf-misc-stego` `ctf-misc-forensics` `ctf-misc-puzzle`

⚡ = 四级深叶子。共 **26 个 skill**（1 master + 3 router + 21 三级 leaf + 1 四级）。

## 安装（把 skill 拷到 Claude Code / reasonix 的加载路径）

```bash
git clone https://github.com/threed33/ctf-skills.git ~/projects/ctf-skills
bash ~/projects/ctf-skills/scripts/install.sh
```

`install.sh` 把仓库 `skills/ctf-*` **拷贝**为 `~/.claude/skills` 与 `~/.reasonix/skills` 下的真身副本（覆盖旧副本）。skill 文件很小（全部 ~320K），copy 模式对加载器最稳、无 symlink 依赖。

**日常同步**（copy 模式有三份：仓库 canonical + 两个加载副本）：

```bash
bash scripts/sync.sh          # pull（默认）：~/.claude 工作副本 → 仓库 + ~/.reasonix，再 git commit && push
bash scripts/sync.sh push     # 仓库 → 两侧（拉了新内容后分发）
bash scripts/sync.sh status   # 三方 diff 概览
```

校验：`bash scripts/verify-tree.sh`。

## 目录

```
skills/                     26 个 ctf-* skill（每个一个 SKILL.md）
docs/SKILLTREE.md           架构详解（背景 / 调用机制 / 四级规则 / 维护指南）
scripts/
  install.sh                把仓库 skills 拷贝为两侧加载路径下的真身副本
  sync.sh                   仓库 ↔ 两侧副本同步（pull / push / status）
  verify-tree.sh            校验三方一致 + 路由表引用闭合
```

## 知识增长纪律

每解一道题的细节经验，写进**对应叶子**（不进总纲）。新考点才新建 leaf + router 路由表加一行；新的跨切面方法论才动总纲。判据永不变：「某漏洞怎么打」→ leaf；「做题怎么做」→ 总纲。详见 [`docs/SKILLTREE.md`](docs/SKILLTREE.md)。

## 与相关项目的关系

- **hack-skills-main**（102 子技能渗透 playbook 库）：CTF leaf 的**深度参考**——穷尽技巧 / WAF 矩阵 / 真实 CVE 时，leaf 用 `hack-skills-main/skills/<x>/SKILL.md` 链接指向它。本仓库**不包含**它，保持外部引用。
- **auto-pentest**：与 ctf-master 并列的第二种模式（授权渗透 vs 比赛解题），不属本仓库。

## 数据来源声明

★ leaf 的实战结晶来自 **TopSecCTF（2026-07-31）**，含该赛事真实 flag 与靶机 IP（赛事已结束、靶机为临时实例）。仅作方法论沉淀与个人能力复盘。

## License

MIT
