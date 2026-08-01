---
name: ctf-crypto
description: CTF 密码学解题工作流（二级总纲：工作流骨架 + 三级 leaf 路由表 + 跨切面纪律）。触发词：CTF-crypto、CTF 密码学、RSA、古典密码、CTF 编码题、pairing、白盒、加密服务、decrypt oracle。与 auto-pentest 并列，不互调流程。
---

# CTF 密码学解题工作流（二级 router）

> **定位**：CTF crypto 方向。主 agent 自包含流水线，**不依赖 vulnclaw**，纯工具链（venv + RsaCtfTool + hashcat + 脚本 + 源码复用）。
> **CTF vs 渗透**：这是解题模式（拿 flag 即止、不写修复）；渗透走 `auto-pentest`，两者并列不互调。
> **本文件只管"做什么"**：工作流骨架 + 路由表 + 纪律。**"这个考点怎么打"的每漏洞 payload / 攻击决策树 / 工具细节全部下沉到三级 leaf**——识别到考点就调对应 leaf，不在本文件翻细节。
> **CTF 原则**：拿 flag 即止、不臆想、写解题链不写修复建议、严格区分"已确认"与"推测"。

## 三级 leaf 路由表

> 识别到该考点就调对应 leaf，不在本文件翻细节。"识别特征"列与各 leaf 的 frontmatter description 对齐。

| 识别特征 | 调用 leaf |
|---|---|
| 编码识别 / base64 / base32 / base16 / hex / base85 / urlencode / 多层递归解码 / 编码套娃 / HTML 实体 / %XX | `ctf-crypto-encoding` |
| 古典密码 / ROT / Caesar凯撒 / 凯撒移位 / 维吉尼亚 Vigenère / XOR 异或 / 替换密码 / 词频-频率分析 / Morse 摩斯 / 培根 Bacon / ASCII 移位 | `ctf-crypto-classical` |
| RSA / n e c p q d / 公钥 PEM / e=3 低指数 / 小明文直接开方 / Wiener（e 大 d 小）/ 共模 same-n 不同-e GCD / Fermat 分解（p q 相近）/ factordb / Coppersmith 小根 / 相关明文 Franklin-Reiter / resultant / 多变量拼接 flag 分块 | `ctf-crypto-rsa` |
| hash / md5 / sha1 / sha256 / hashcat / crackstation / 彩虹表 / 带盐哈希 / NTLM / bcrypt / scrypt / 哈希长度扩展 / HMAC / Merkle-Damgard | `ctf-crypto-hash` |
| AES / DES / Padding Oracle / ECB / CBC / 比特翻转 / 块密码 / 加解密 oracle / OpenSSL Salted__ 头 / DES 弱密钥 | `ctf-crypto-symmetric` |
| 白盒 / 有源码 / pairing 双线性对 / BLS12-381 / IBE 基于身份加密 / 同态 homomorphic / 非标准方案 custom scheme / encrypt-decrypt oracle 解密预言机 / 重随机化 re-randomizable / CCA / malleability / Rust/Go/Sage/arkworks | `ctf-crypto-whitebox` |

### 路由协议（多指纹命中时怎么选）

- **先剥编码再判考点**：密文像 base 家族 / hex / url → 先 `ctf-crypto-encoding` 逐层剥离，剥到不可读再判古典 / RSA / Hash / 对称。编码往往是第一层套娃。
- **有源码优先白盒**：附件给完整源码（Rust crate / Go pkg / Sage `.sage` / Python）或题面是「构造加密服务 + decrypt oracle」→ 直接 `ctf-crypto-whitebox`，RsaCtfTool 用不上，靠白盒分析 + 攻击构造。
- **多考点串联**：base64 解完是 RSA（→ encoding 再 rsa）、密文长度 16 倍数给 n e（→ rsa 出 key 再 symmetric 解）、hash 校验签名的 RSA（→ rsa 再 hash）。按数据流顺序串多个 leaf，不要在一个 leaf 里硬塞。
- **拿不准就走最宽入口**：RSA 不确定攻击类型时 leaf 内有「全攻击」兜底；古典不确定位移时 leaf 内有遍历兜底。本文件不替你选具体攻击，只路由到 leaf。

## 阶段 0：就绪自检

| 依赖 | 自检命令 | 状态 |
|---|---|---|
| venv python | `/home/threed/ctf/venv/bin/python -c "import Crypto,sympy,gmpy2,requests"` | ✅ 全装（pycryptodome/sympy/gmpy2/requests/cryptography/factordb-pycli） |
| RsaCtfTool | `/home/threed/ctf/venv/bin/python -m RsaCtfTool --help` | ✅ 已 `--no-deps -e` 注册，`-m` 可跑 |
| hashcat | `which hashcat` | ✅ 6.2.6 |
| hashid | `which hashid` | ⚠️ 未装，降级在线识别 / 按长度猜 |
| Rust（白盒题用） | `~/.cargo/bin/cargo --version` | ✅ rustc 1.90（**不在 PATH，用全路径**） |

**工具降级表**：`hashid` 未装 → 在线 hash-identifier 或按长度猜（md5=32 / sha1=40 / sha256=64 / `$1$`/`$2y$`/`$6$` 看 header）；靶机服务轻量，**线程 ≤5–10、别高并发 fuzz**。

## 工作流阶段骨架

**router 与 leaf 的边界**：本文件只做路由——识别考点 + 调 leaf + 兜纪律。每考点的攻击方法、决策树、命令、时限运算、范例一律在对应 leaf。别在 router 里重复堆 payload，也别在 leaf 里重写工作流骨架。

**阶段 1 · 侦察 / 识别**
1. 判断编码/加密类别：按字符集 + 长度 + 填充识别 base 家族；PEM / JWT(`eyJ`) / `Salted__` / 给出 n e c / 公钥 / 密文特征 / **有源码 → 白盒**。
2. 输出题目标签（编码 / 古典 / RSA / Hash / 对称 / 白盒）→ 对照上方路由表确定调哪个 leaf。
3. **已知/泄露题快查（深度投入前必做）**：拿题面/源码指纹（题名、关键常量、banner、附件名、源码哈希）先搜 GitHub / CryptoHack / CTFtime writeup。命中 → 直接复用 writeup，别重造轮子或踩乌龙题坑（例：`f,l,ag++` 是 Dreamhack `fl and ag`(ch.939) 复仇，作者 solver 全公开）。这一步对所有考点通用，不只古典/白盒。

**阶段 2 · 扫描 / 专项利用**
**识别漏洞/考点类型 → 查上方路由表 → 调对应 `ctf-crypto-*` leaf，不在本文件堆 payload。** leaf 内含每考点的攻击决策树、命令、时限运算纪律、范例。多考点套娃（如 base64 解完是 RSA）按序串联多个 leaf。

**阶段 3 · flag 提取与校验**
1. 多层编码递归（base64 套 base32 套 hex…）循环解码直到出 flag。
2. flag 格式校验：`flag\{[^}]+\}` 或题目指定格式。
3. 未出 flag 则回阶段 1 重新识别（可能误判类别）。

**阶段 4 · 总结报告（每题必写）**
写到 `/home/threed/ctf/crypto/solve_{题目名}.md`，结构同 ctf-web（目标概况 / 考点清单 / 解题路径图 / 获取数据 / flag 状态 / 解题思路链 / 工具链），flag 追加 `/home/threed/ctf/crypto/flags.txt`。白盒题报告须含**方案分析表 + 攻击数学证明 + 验证表（含自定义数据）**。
> **AK 模式**（见 ctf-master）：跳过报告，拿到 flag 立即返回 `flag + 一句话解法 + 关键脚本/命令`，报告后置到 Phase 3。

## 跨切面纪律（所有考点通用，必守）

1. **本地验证用自定义数据**：**不能只用题目默认值**（默认 flag/样例输入）验证。默认值"通过"是假阳性——无法区分"实现正确恢复"和"实现总吐默认值"。本地用**自定义 flag/明文**（区别于默认）跑通，才证明实现正确。
2. **密文长度 = 明文长度探针**：`enc_flag = flag XOR kdf` 这类结构，密文长度即明文长度。远程密文长度恒等于默认值长度 ⇒ 远程未注入真实明文（环境问题），不必猜、别硬记 flag。
3. **数学证明在先**：先证明攻击数学正确（如 `dec(CT')=K`），再用自定义数据验证实现，最后才信结果。拿到异常输出（如 test_flag）时靠数学底气排查实现/环境，而非怀疑攻击思路。
4. **所有 Python 一律用 `/home/threed/ctf/venv/bin/python`**：pycryptodome/sympy/gmpy2 只在 venv，系统 python3 `import Crypto` 会失败。
5. **RsaCtfTool 用 `-m` 且 `--no-deps -e` 注册**：正确调用 `/home/threed/ctf/venv/bin/python -m RsaCtfTool --publickey pub.key --uncipherfile flag.enc --attack <attack>`；仓库已改 src-layout，**不要用 `python3 RsaCtfTool.py`**（根目录无此文件）；注册 `pip install --no-deps -e /home/threed/ctf/tools/RsaCtfTool/`（**必须 --no-deps**，否则 pyproject 锁的旧版降级 venv 新版）。

## 输出规则

| 规则 | 路径 |
|---|---|
| 总结报告 | `/home/threed/ctf/crypto/solve_{题目名}.md` |
| flag | `/home/threed/ctf/crypto/flags.txt` |

## 使用方式

输入："这道 crypto 题：n=xxx e=65537 c=xxx"（→ `ctf-crypto-rsa`）
或："这串密文 base64 解完像 RSA，帮我解"（→ `ctf-crypto-encoding` → `ctf-crypto-rsa`）
或："这道题给了 Rust 源码，pairing 加密 + decrypt oracle"（→ `ctf-crypto-whitebox`）

触发后按阶段 0 → 4 执行：先就绪自检，识别考点调 leaf 拿细节，每题必出总结报告（AK 模式除外）。
