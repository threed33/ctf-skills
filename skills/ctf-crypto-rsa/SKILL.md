---
name: ctf-crypto-rsa
description: CTF RSA 攻击 playbook。识别/触发：RSA / 公钥 PEM / 给出 n e c p q d / 低指数 e=3 / 小明文 m^e<n 直接开方 / Wiener（e 大、d 小） / 共模 same n 不同 e → GCD / Fermat 分解（p/q 相近） / factordb 在线分解 / Coppersmith 小根 / 相关明文 related-message Franklin-Reiter / resultant / 多变量拼接 flag 分块。碰到 n e c、公钥 PEM、e=3、双密文共模、p q 相近、相关明文、限时 resultant 等指纹时由二级 ctf-crypto 路由表调用本 leaf，专项解决"这个 RSA 考点怎么打"。
---

# CTF RSA 解题 playbook

> **定位**：CTF skill 树三级 leaf（知识锚点）。由二级 `ctf-crypto` 路由表按识别特征调用；本文件只讲"这个考点怎么打"，不重复工作流。
> **CTF 原则**：拿 flag 即止、不写修复、不臆想、区分确认与推测。crypto 无靶机出网问题，但限时题要先选对算法域（见 5）。

## 识别特征（什么时候调我）
- 附件给 `pubkey.pem` / `-----BEGIN PUBLIC KEY-----`，或源码 `from Crypto.Util.number import *` 后 print 出 `n, e, c`。
- `e` 异常：`e=3`（低指数）、`e=0x101`/`e=257`（常配 related-message）、`e` 很大（Wiener，d 小）。
- 多组 `(e_i, c_i)` 共享同一个 `n`（共模攻击），或给两个相关明文加密（`m` 与 `a·m+b`，Franklin-Reiter）。
- `n` 特征：极小（<300bit，factordb/直接分解）、两素数相近（Fermat，`p-q` 小）、多素数（在线分解或针对性）。
- 给 `flag = A|B|C` 分块 + 各块密文 + 总密文（拼接型 related-message，见 flag_land 结晶）。
- 报错含 `DomainError`、`fmpz_mod_poly`、`resultant`、`signal.alarm(10)`（限时 resultant 题，见 5）。

## 核心攻击手法

### 决策树（按特征选攻击，照此分支）
```
n 极小(<300bit) ──────────────► factordb / yafu / 直接分解 → d=e^-1 mod φ → m=c^d
e=3 且 c.bitlen < n.bitlen ───► 小明文：m³<n 无模约减，gmpy2.iroot(c,3) 开立方
e=3 但 m³>n ─────────────────► Coppersmith（m 高位已知 / 短 padding / stereotyped）
e 大(>65537)、d 小 ───────────► Wiener（连分数收敛）
同一 n、两个 e1,e2 且 gcd=1 ──► 共模：m = c1^a·c2^b mod n，a=e1^-1,b=-e2^-1
p,q 相近 ─────────────────────► Fermat 分解：从 √n 往上试 x，x²-n = y²
给 m 和 a·m+b 两密文 ─────────► Franklin-Reiter related-message（单变量 Z_N gcd）
拼块 flag + 各块密文 + 总密文 ─► 多变量 resultant + LLL → 下钻 ctf-crypto-rsa-related-message
```

### 1. 小明文 / 低指数 e=3（c < n 直接开方）
```python
import gmpy2
from Crypto.Util.number import long_to_bytes
m, exact = gmpy2.iroot(c, 3)   # e=3 时
assert exact                   # exact=False → m³>n，转 Coppersmith 或试 c+k*n
print(long_to_bytes(int(m)))
```
> 若 `exact=False`：明文回绕了，遍历 `m,k = iroot(c + k*n, 3)`，k=0..少量。

### 2. 共模攻击（same n, e1≠e2, gcd(e1,e2)=1）
```python
from Crypto.Util.number import long_to_bytes
# 扩展欧几里得：a*e1 - b*e2 = 1（视符号调整）
m = pow(c1, a, n) * pow(c2, -b, n) % n
print(long_to_bytes(m))
```

### 3. factordb / 小 n 分解（如 n=3233 → 61×53）
```bash
# 在线：https://factordb.com   粘 n
# 命令行（已知 n）：直接 sage/yafu，或 RsaCtfTool
/home/threed/ctf/venv/bin/python -m RsaCtfTool --publickey pub.key --uncipherfile flag.enc --attack all
```
```python
# 拿到 p,q 后：d=e^-1 mod (p-1)(q-1)，逐密文解密
p,q,e=61,53,65537; phi=(p-1)*(q-1); d=pow(e,-1,phi)
ct=[1421,669,1668,641,2159,325,119,325,2726,2790,669,589]
print("".join(chr(pow(c,d,3233)) for c in ct))   # 逐字符 RSA
```

### 4. Fermat 分解（p≈q）
```python
from gmpy2 import isqrt, is_square
x = isqrt(n) + 1
while not is_square(x*x - n): x += 1
y = isqrt(x*x - n); p, q = x+y, x-y
```

### 5. related-message / resultant —— 下钻 `ctf-crypto-rsa-related-message`
> 相关明文（Franklin-Reiter）、拼块 flag 多变量 resultant、限时 resultant 题的**完整攻击链 + 时限纪律（ZZ 提升 / half-GCD / CRT / Hadamard 界）+ f,l,ag++ 实战结晶**全部在四级子 leaf。本 leaf 只做路由：命中此分支 → 调入 `ctf-crypto-rsa-related-message`。提示：复合模数 N 上 flint `fmpz_mod_poly.resultant` 报 `DomainError`、朴素 PRS O(e²) ~1100s 撞限时墙——正解是提升 ZZ 跑模 resultant，详见子 leaf。

## CTF 实战结晶
- **rsa9（低指数 e=3）**：给 n(1024bit)/e=0x3/c。关键判定 `c.bit_length()=501 < n.bit_length()=1024`，即 `m³<n` 无模约减。`gmpy2.iroot(c,3)` 精确命中（exact=True），`long_to_bytes` → `flag is md5("SmallM")`，再 `hashlib.md5(b"SmallM")` 得 `flag{81a8dc8a46c83f0681a62e515dcb5f0c}`（题目嵌套一层 MD5）。自定义 `b"custom_verify_123"` 回环验证 exact=True，非默认值假阳性。脚本 `/home/threed/ctf/crypto/solve_rsa9.py`。
- **RSA基础（GZCTF，小 n 逐字符）**：n=3233(12bit)→61×53，e=65537，12 个空格分隔密文。d=pow(e,-1,3120)=2753，逐字符 `pow(c,d,3233)` → ASCII 拼接 `[GZCTF_FLAG]` 占位符 → 真实 `GZCTF{4da42999}`。决策树命中"n 小→直接分解"分支。
- **f,l,ag++（限时 related-message+LLL，10s）**：完整链路（归一化→双变量 resultant 消元→2D 格）+ 性能墙教训（ZZ 提升 resultant，1100s→5s）+ 开题先查，全在四级子 leaf **`ctf-crypto-rsa-related-message`**（含 memory [[reference-rsa-related-message-resultant]]、[[feedback-crypto-perf-wall-algorithmic]]、[[feedback-check-known-leaked-challenge]]）。

## 工具命令
```bash
# venv（pycryptodome + gmpy2 已装）
/home/threed/ctf/venv/bin/python solve.py

# RsaCTFTool（src-layout，必须 -m，别用 RsaCtfTool.py）
/home/threed/ctf/venv/bin/python -m RsaCtfTool --publickey pub.key --uncipherfile flag.enc --attack all
/home/threed/ctf/venv/bin/python -m RsaCtfTool --publickey pub.key --uncipherfile flag.enc --attack wiener
/home/threed/ctf/venv/bin/python -m RsaCtfTool --publickey pub.key --uncipherfile flag.enc --attack fermat

# PEM 读 n,e
/home/threed/ctf/venv/bin/python -c "from Crypto.PublicKey import RSA; k=RSA.import_key(open('pub.key').read()); print(k.n, k.e)"

# 在线分解
# factordb.com  粘 n ；或 d-n1606.factordb.com/api/?query=<n>

# Sage（related-message / resultant / Coppersmith / LLL 必备）
sage solve.sage
```

## 深度参考（穷尽技巧时加载）
- hack-skills-main/skills/rsa-attack-techniques/SKILL.md
- hack-skills-main/skills/lattice-crypto-attacks/SKILL.md

## 关联 leaf
- `ctf-crypto`：本 leaf 的二级路由表（RSA 决策树 + RsaCtfTool 调用纪律 + 白盒分支在此之上）。
- `ctf-crypto-hash`：RSA 题常嵌一层 MD5/SHA（如 rsa9 的 `flag is md5("SmallM")`），拿到明文后转 hash。
- `ctf-crypto-classical`：极少串链，但"逐字符加密的整数串"形态与逐字符 RSA 相似，识别时别走错（看是否有 n e d 模数）。
