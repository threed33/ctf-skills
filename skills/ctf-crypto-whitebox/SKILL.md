---
name: ctf-crypto-whitebox
description: CTF 白盒/非标准密码方案 攻击 playbook。识别/触发指纹：白盒/有源码/white-box/pairing/双线性对/BLS12-381/IBE/基于身份加密/同态/homomorphic/非标准方案/custom scheme/encrypt-decrypt oracle/解密预言机/重随机化/re-randomizable/CCA/CCA2/malleability/可塑性/Rust/Go/Sage/arkworks。碰到附件给完整源码（Rust crate、Go pkg、Sage .sage）、题面是「构造一个加密服务 + decrypt oracle 但禁原密文」、密文对随机数线性依赖、pairing 库 (arkworks/blst/py_ecc) 等场景时，由二级 ctf-crypto 路由表调用本 leaf，专项解决"这个非标准方案怎么打"。
---

# CTF 白盒/非标准密码方案 解题 playbook

> **定位**：CTF skill 树三级 leaf（知识锚点）。由二级 `ctf-crypto` 路由表按识别特征调用；本文件只讲"这个考点怎么打"，不重复工作流。
> **CTF 原则**：拿 flag 即止、不写修复、不臆想、区分确认与推测。靶机常不出网 → 本考点天然就是本地数学推导 + 单次 oracle 查询，无 OOB 需求。

## 识别特征（什么时候调我）
- 附件是**完整源码项目**（Rust `Cargo.toml`+`common`/`server` crate、Go module、Sage `.sage`/`.py`），不是黑盒二进制 → 白盒，先读代码不先爆破。
- 题面/服务形式是 **encrypt + decrypt oracle**：服务给你加密一个 K/flag，再让你提交一个密文给 decrypt，但**禁止提交「原始挑战密文」**(拒绝 `CT' == CT` 或只允许有限次 decrypt) → 典型 CCA 场景，目标是重随机化 / 改写密文绕过相等性检查。
- 源码出现 **pairing 库**：Rust `ark-bls12-381` / `arkworks`、Go `blst` / `bn256`、Python `py_ecc` / `bn256` / `blspy`；有 `pairing(e)`/`G1`/`G2`/`GT`/`Fr` 类型 → pairing-based 方案。
- 密文结构 **(c1, c2, c3, ...)** 各分量对随机数 `t`/`r` **线性依赖**（`c2 = g1·t`、`c3 = q·t` 这种标量乘法直出）→ 强烈指向 re-randomizable / malleable。
- 关键词出现：IBE / 基于身份 / 同态 / homomorphic / proxy re-encryption / re-randomizable / CCA / 「不允许重复解密」「每个密文只能解一次」。
- 密文/明文末尾有 `XOR` / `kdf(K, len)` / `enc_flag = flag XOR keystream`：flag 不直接是 decrypt 输出，而是用某个 derived key 异或出来 → 目标是恢复那个 K 而非 flag 本体。

## 核心攻击手法

### 总方法论（白盒四步）
1. **识别方案**：从源码 `setup`/`keygen`/`enc`/`dec` 函数对照标准构造（ElGamal / IBE / Boneh-Franklin / Boneh-Boyen / CCA 变体），判断是哪一族、用了什么假设。
2. **找弱点**：逐项检查 — ①密文对随机数是否线性（→ malleable / re-randomizable）；②oracle 的限制语义（是 `==` 还是内容校验？是否记历史？是否只校验某一分量？）；③参数是否弱（小子群、可逆矩阵、`q`/`id` 可控）；④是否混淆了 G1/G2/GT 运算导致可消元。
3. **数学证明**：把改写后的密文 `CT'` 代回 `dec` 公式，**符号推导**出 `dec(CT') == dec(CT)`（或 == 你想要的目标值），不靠试。证明成立才写 exploit。
4. **源码语言复用附件库**：Rust 题复用附件 `common` crate 做 parse/serialize/群运算（压缩点格式 100% 兼容），Python 题用同一库的 binding。**不要**自己拿另一个库硬解序列化（ark 压缩格式 Python 常不兼容，会卡在点编码上）。

### 手法 A：re-randomizable encryption（密文对 t 线性 → 重随机化绕 oracle）
前提：`c1 = K·pk^t`（或 `M·e(...)^t`），`c2 = g1·t`，`c3 = q·t`，oracle 只拒绝 `CT'==CT`。
令 `t → t+s`（取 `s=1` 最省），重随机化只需群加法 + GT 乘法：

```python
# s=1：所有元素 banner 都已给，无需标量乘法/私钥
c1p = c1 * pk            # GT 乘法：K·pk^(t+1)
c2p = c2 + g1            # G1 加法：g1·(t+1)
c3p = c3 + q             # G2 加法：q·(t+1)
# 提交 (c1p, c2p, c3p)：c2p != c2，绕过 == 检查；dec 仍得 K
```

为什么仍解出 K：`dec = c1 · e(s2,c3) / e(c2,s1)`，把 `t+1` 代入后 `e(s2,q)/e(g1,s1) = pk^(-1)` 会把多出来的 `pk^(t+1)` 正好消掉，留下 `K`。**先在草稿上推一遍这个消元，确认再写码**。

### 手法 B：CCA malleability（XOR / 加法同态）
- **ElGamal / Paillier 加法同态**：`Enc(m1) · Enc(m1) = Enc(m1+m2)`，可在密文上加常数、标量倍，让 decrypt 输出可控偏移 → 配合 `enc_flag = flag XOR kdf(K)` 改 K 或读取关系。
- **流密码式 XOR 密文**：`c = m ⊕ KDF(K)`，若能求一个已知明文 `m0` 的密文，`KDF(K) = c ⊕ m0` 直接还原密钥流。

### 手法 C：oracle 限制语义漏洞
- oracle 只比较 `c1` 不比 `c2`：只重随机化未被比较的分量即可。
- oracle 记历史但按 **序列化字节串** 比较：换序列化（压缩/非压缩、大小端、附加 padding）就过。
- oracle 限次但允许**任意「合法」密文**：提交一个你已知明文 `M0` 的自造密文，拿回 `KDF(K0)`，反推密钥流 → 解 `enc_flag`。

### 手法 D：pairing 方案参数弱点
- `id` / `q = H1(id)` 可控：换 id 制造可消元关系，或求两个 id 使 `q1/q2` 已知。
- `mpk` / `pk` 在 banner 明文给：很多 pairing CCA 题把 `mpk^ξ` 直接泄露，使重随机化不需私钥。
- 子群 / 坐标退化：检查曲线参数是否落到小阶子群，可离散对数还原 `t`。

## CTF 实战结晶

### 【可重随机化 pairing 加密】（BLS12-381 / Rust arkworks / decrypt oracle 禁原密文）— 2026-07-29
- **附件**：Rust 项目（`common` 加密库 + `server` decrypt oracle），arkworks 0.5，BLS12-381；远程 `ncat --ssl host 9999`。
- **方案**（白盒读源码）：
  - `setup`: `msk = h·a (G2)`，`mpk = e(g1, msk)`
  - `enc(pk,id,K)`: `c1 = K·pk^t`，`c2 = g1·t`，`c3 = q·t`（`q = H1(id)`）
  - `dec`: `c1 · e(s2,c3) / e(c2,s1)`，对任意 `t` 消去 `pk^t` 还原 `K`
- **漏洞**：`c1/c2/c3` 全部线性依赖 `t` → re-randomizable。
- **确切 trick（s=1 重随机化）**：
  ```
  1. 收 banner: id | DST | pk | q=H1(id) | c1 | c2 | c3 | enc_flag
  2. 重随机化 s=1:  c1'=c1*pk,  c2'=c2+g1,  c3'=c3+q   (1 GT mul + 2 群加法)
  3. 提交 c1'|c2'|c3'  (c2'≠c2，绕 oracle == 检查)
  4. oracle 返回 kdf(K, flag_len)   ← K 与原 pairing_key 相同
  5. flag = enc_flag XOR key
  ```
- **为什么 dec(CT')=K**：`c1'·e(s2,c3')/e(c2',s1) = K·pk^(t+1)·[e(s2,q)/e(g1,s1)]^(t+1) = K·pk^(t+1)·pk^(-(t+1)) = K`。
- **实现选型**：Rust `client rerand` 复用 `common` 的 parse/serialize/hex 做 BLS12-381 群运算（ark 压缩格式 100% 兼容，Python 库难兼容）；Python `exploit.py` 用标准库 `ssl` 做传输 + 调 rerand + XOR。
- **验证教训（重要）**：
  - 本地默认 FLAG 返回 `RCTF{test_flag}` 不算数；**必须设自定义 FLAG**（`RCTF{custom_verify_XYZ_123}`）验证 client 能恢复任意 flag，才能排除「实现 bug」vs「client 总吐 test_flag」。
  - **`enc_flag` 长度是 flag 注入探针**：`enc_flag = flag XOR kdf`，长度 = flag 长度。远程 `enc_flag` 恒 15 字节 = `test_flag` 长度 → 直接断定远程 FLAG 环境变量未注入，落在默认值，**这是环境问题，不是攻击/实现问题**。数学证明让你坚信攻击，不被 test_flag 干扰。
- **结论**：本地任意 flag 都能恢复（攻击 100% 正确）；远程待平台修复 flag 注入，同一 exploit 直接拿真实 flag，无需改代码。
- **源码**：`/home/threed/ctf/crypto/pairing_chall/attachment/client/src/main.rs`、`exploit.py`；解题报告 `/home/threed/ctf/crypto/solve_pairing_rerand.md`。

## 工具命令

```bash
# Rust 白盒题：复用附件 crate 编译攻击客户端（最稳，序列化零兼容风险）
cd attachment && cargo build --release
SERVER_BIN=./target/release/server ./target/release/client rerand   # 本地

# Python 传输层（ncat --ssl 远程）+ 调 Rust rerand 二进制 + XOR
python3 exploit.py    # 内部 subprocess 调 client rerand，HOST 改实例地址

# SageMath：推导 / 验证 pairing 关系（证明 dec(CT')==K 时用）
sage verify.sage      # 在 GT 上符号化验证消元

# 通用：远程交互探测 banner 格式
ncat --ssl host 9999
openssl s_client -connect host:9999 -quiet   # TLS 交互备选
```

## 深度参考（穷尽技巧时加载）
- `hack-skills-main/skills/lattice-crypto-attacks/SKILL.md`（pairing/格混合、子群弱参数）
- 二级 `ctf-crypto` 路由表（RSA / 古典 / 格 / oracle 等其他 crypto 考点的分流入口）

## 关联 leaf
- `ctf-crypto`（二级路由：本题先由它判定为白盒/非标准方案再下发本 leaf）
- `ctf-web-deser` / `ctf-web-race`：少数白盒 crypto 题以 Web 服务形式出现（PHP/Java 反序列化触发 crypto 逻辑、并发 oracle 双花），串成「Web 入口 → crypto 核心」链
- `ctf-crypto-classical`：当「非标准方案」退化成 XOR / 仿射时降级处理
