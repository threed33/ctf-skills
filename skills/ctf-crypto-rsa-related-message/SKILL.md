---
name: ctf-crypto-rsa-related-message
description: CTF RSA 相关明文/多变量 resultant 攻击 playbook（ctf-crypto-rsa 的四级深叶子）。识别/触发：RSA相关明文/related-message/Franklin-Reiter/resultant/结式/多变量/multivariate/拼接flag分块/flag=A|B|C分块加密/限时/signal.alarm/DomainError/fmpz_mod_poly报错/half-GCD/CRT重构建/Hadamard界/2D格有理重构/LLL/多项式gcd over Z_N/同一n多块密文+总密文。碰到"两明文线性相关(m与a·m+b)"、"flag 拆 f|l|ag 多块各自加密+总密文"、"限时 10s resultant"、"flint fmpz_mod_poly.resultant 报 DomainError"等指纹时，由 ctf-crypto-rsa 决策树调入本 leaf——本 leaf 是全树最深内容，专攻 resultant 类攻击与"撞时限墙"的算法域选择。
---

# CTF RSA related-message / resultant 攻击 playbook

> **定位**：CTF skill 树**四级深叶子**（`ctf-crypto-rsa` 的子节点）。`ctf-crypto-rsa` 决策树命中"相关明文 / 拼块 flag / resultant / 限时"分支时调入本 leaf。本 leaf 只讲 resultant 类攻击 + 时限纪律，不重复标准 RSA 攻击（低指数/Wiener/共模/Fermat 见父 leaf `ctf-crypto-rsa`）。
> **CTF 原则**：拿 flag 即止、不臆想、区分确认与推测。这类题**数学正确性不是瓶颈，算法域选择才是**——撞时限墙先确认算法最优（域上 half-GCD + 并行），别在同一复合模数算法上换库。

## 识别特征（什么时候从 ctf-crypto-rsa 调入我）

- 两明文**线性相关**：给 `m` 与 `a·m+b` 的密文（同 n、同 e）→ 经典 Franklin-Reiter。
- **拼块 flag**：`flag = A|B|C` 分块，各块密文 + 总密文都给（如 `flag = 2^408·f + 2^272·l + ag`，给 f_enc/l_enc/ag_enc/flag_enc）→ 多变量 resultant + LLL。
- `e` 异常偏大且非 65537（`e=0x101=257` 是这类题的高频指纹）。
- 题面带 **限时**（`signal.alarm(10)`、`timeout`）→ 时限纪律必读（§3）。
- 报错含 `DomainError` / `fmpz_mod_poly` / `resultant` → 你已踩复合模数陷阱（§3）。

## 核心攻击手法

### 1. 单变量 Franklin-Reiter（m 与 a·m+b，同 n 同 e）

两相关明文 `m1=m`、`m2=a·m+b`，密文 `c1`、`c2`。构造两多项式，**gcd 即 (x−m)**：

```python
# Z_N[x] 上（N=pq）。需单变量，前导系数 1 故可逆，gcd 正常跑
from Crypto.Util.number import long_to_bytes
# PR.<x> = PolynomialRing(Zmod(n))
# f1 = x^e - c1
# f2 = (a*x + b)^e - c2
# m = -gcd(f1, f2).roots()[0][0]   # 或 monic 后取根
print(long_to_bytes(int(m)))
```

单变量、前导系数可逆 → 普通 `Z_N` gcd 即可，**不需要 §3 的 ZZ 提升**。这是入门版。

### 2. 多变量 resultant（拼块 flag，双变量消元）

flag 拆成已知位移的块（`flag = s1·A + s2·B + C`，C 常数），给 A_enc/B_enc/flag_enc。三多项式：

```python
# 环 Z_N[y][x]（双变量）
# f1(x,y) = (s1*x + s2*y + C)^e - cF      # flag 结构
# f2(x)   = x^e - cA                       # A 的密文
# f3(y)   = y^e - cB                       # B 的密文
# Step1: g(y) = Res_x(f1, f2)              # 消 x，只剩 y 的多项式
# Step2: B = -root(gcd(g, f3));  A = -root(gcd(f1(y=B), f2))
# Step3: 2D 格 [[1,A],[0,N]] LLL/Gauss → (ag, f) 有理重构（A=f/ag，块远小于 N）
```

**归一化先做**：所有密文除以某块密文（如 `ag_enc⁻¹`）→ 常数项变 1、少一个未知数（`cA=f_enc·inv_ag`，使 `flag/ag = s1·A + s2·B + 1`）。

`Res_x(f1,f2)` 这步是性能瓶颈——**必须在 ZZ 上跑**（§3），否则合数 N 上又慢又报错。

### 3. 时限纪律（撞墙必读，全树最硬一节）

> **核心认知：双变量 resultant `Res_x(f1,f2)` 是 y 的整数系数多项式**（Sylvester 行列式定义，与系数除法无关）。所以**别在 `Z_N` 上跑 Euclidean，把 f1,f2 当整数系数多项式提升到 `ZZ` 跑模 resultant**。

**复合模数陷阱（为什么不能直接用 flint）**：
- `Z_N`（N=pq 合数）上多项式 gcd/resultant 要对前导系数求逆 → 频繁无逆元 → flint `fmpz_mod_poly.resultant/gcd` **直接 DomainError**；
- python-flint **不释放 GIL** → 多线程零加速（并行只能多进程）；
- 朴素 subresultant PRS 是 O(e²) 大数乘，e=257 → ~66k 次，单核 ~1100s——**算法层本质慢，换库救不了**。

**唯一快法——提升到 ZZ（Sage 一行，内部自动模算法）**：
```python
R.<x,y> = ZZ[]                       # 整数系数环，不是 Zmod(N)！
g = f1.resultant(f2, x)              # cA,cB,cF 用 [0,N) 代表元，不 mod N
# 末尾再在 Z_N 上 g mod (y^e - cB) 折叠 → 取根 → 2D 格
```

**三个加速来源（相乘 ~220×，1100s→~5s）**：
1. **word 域算术**：内部走多素数 `nmod_poly`（~60-bit NTT）每次操作比 2048-bit fmpz 快 10²–10³×；
2. **half-GCD** = O(M(e)log e)，朴素 PRS 是 O(e·M(e))，~30× 降阶——**只在域上可用**（要逆前导系数），这正是必须提升 ZZ 的根本原因；
3. **多素数独立** → multiprocessing 真并行（每进程独立 GIL），~8–16×。

⚠️ **CRT 素数个数要盖住"整数 resultant 系数的 Hadamard 界"**（巨大，~10³–10⁴ 个小素数），**不是只盖 N**；重建出**精确整数** resultant 后才 mod N（因 mod N 不与 mod p 交换：`cA=a−kN` 时 `(a mod N) mod p ≠ a mod p`）。

**收尾**：2D 格 `[[1,A],[0,N]]` 有理重构（LLL/Gauss）恢复小分子/分母（ag、f 等，块远小于 N）。

**备选（无 Sage，保留 Z_N PRS）**：朴素 PRS 不变，用 flint/Kronecker 做乘法后端，把每步内**独立的逐 x-系数 cross-multiply 按系数切片丢多进程**（process 非 thread）。也能到秒级。

## CTF 实战结晶

**f,l,ag++（限时 related-message + LLL，10s，原题 Dreamhack `fl and ag` 强化版）**：
- `flag = f(17B) | l(17B) | ag(34B)`，即 `flag = 2^408·f + 2^272·l + ag`，给 f_enc/l_enc/ag_enc/flag_enc，`e=0x101=257`。正解名 "Multivariate Franklin-Reiter related-message attack + LLL"。
- 链路：① 归一化 `inv_ag=ag_enc⁻¹`，`cA=f_enc·inv_ag`、`cB=l_enc·inv_ag`、`cF=flag_enc·inv_ag`，使 `flag/ag=2^408·A+2^272·B+1`；② `f1=(2^408·x+2^272·y+1)^e−cF`、`f2=x^e−cA`、`f3=y^e−cB`，环 `Z_N[y][x]`；③ `Res_x(f1,f2)` 消 x 得 `g(y)`；④ `B=−root(gcd(g,f3))`、`A=−root(gcd(f1(y=B),f2))`；⑤ 2D 格 `[[1,A],[0,N]]` → (ag,f)，`l=B·ag`，重组 flag。
- **性能墙（亲历）**：朴素 Z_N PRS 实测单核 ~1100s（it=125 已 273s）；试 python-flint `fmpz_mod_poly.resultant` 在合数 N 上 DomainError + 不释放 GIL。**5s 正解 = 提升到 ZZ `f1.resultant(f2,x)`**（多素数 nmod_poly half-GCD + CRT + 并行），素数个数盖 Hadamard 界。数学正确性早就验证（e=5/400-bit 端到端 MATCH=True），瓶颈纯在算法域。
- **开题先查（关键教训）**：此题是公开题复仇，作者 writeup + ex.sage 全公开在 GitHub `soon-haari/my-ctf-challenges`，Neobeo 的 ~5s 脚本在 CryptoHack Discord。开题搜 5 分钟 GitHub/CryptoHack/CTFtime 命中即复用，别闷头重造。
- 存档：`/home/threed/ctf/crypto/flag_land/`（task.py 题面；solve.py/solve_flint.py = 验证正确但慢的 Z_N PRS；lessons_f_l_and_ag.md = 完整复盘）。

## 工具命令

```bash
# Sage（resultant / half-GCD / CRT / LLL 必备，首选）
sage solve.sage
# 内部关键一行：R.<x,y>=ZZ[]; g = f1.resultant(f2, x)

# 无 Sage 时纯 Python+gmpy2(Kronecker) 能跑通但慢（~1100s），仅作验证
/home/threed/ctf/venv/bin/python solve.py
```

## 深度参考（穷尽技巧时加载）
- **memory [[reference-rsa-related-message-resultant]]** —— 时限纪律权威精简版（首选查这个）
- **memory [[feedback-crypto-perf-wall-algorithmic]]** —— 撞时限墙先换算法不换库
- hack-skills-main/skills/rsa-attack-techniques/SKILL.md
- hack-skills-main/skills/lattice-crypto-attacks/SKILL.md —— Coppersmith / LLL 格归约

## 关联 leaf
- `ctf-crypto-rsa`（**父 leaf**）：标准 RSA 决策树（低指数/Wiener/共模/Fermat/factordb）；命中"相关明文/resultant/限时"分支才下钻到本 leaf。
- `ctf-crypto-hash`：related-message 解出明文后常嵌一层 MD5/SHA（如 flag = md5(明文)），转 hash leaf。
