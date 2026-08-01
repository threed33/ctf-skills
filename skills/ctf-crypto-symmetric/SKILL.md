---
name: ctf-crypto-symmetric
description: CTF 对称密码 AES/DES 攻击 playbook。识别/触发：AES/DES/Padding Oracle/ECB/CBC/比特翻转/块密码/oracle/Salted__。碰到密文长度 16 字节倍数、IV 可控、加解密 oracle 回显 padding 对错、ECB 同明文产生同密文块、CBC 比特翻转篡改解密结果、OpenSSL Salted__ 头、DES 弱密钥/ECB 模式可重放等指纹时，由二级 ctf-crypto 路由表调用本 leaf，专项解决"这个对称考点怎么打"。
---

# CTF 对称密码 AES/DES 解题 playbook

> **定位**：CTF skill 树三级 leaf（知识锚点）。由二级 `ctf-crypto` 路由表按识别特征调用；本文件只讲"这个考点怎么打"，不重复工作流。
> **CTF 原则**：拿 flag 即止、不写修复、不臆想、区分确认与推测。靶机常不出网 → 优先本地回显路径（union/error/盲注/文件读式 oracle）。

## 识别特征（什么时候调我）
- 密文长度是 **16 字节倍数**（AES）/ 8 字节倍数（DES/3DES），常 base64/hex。
- 接口提供 **加/解密 oracle**：你提交密文，服务返回"padding 错误"vs"成功"的响应差异 → Padding Oracle。
- **IV 可控**且密文前缀即 IV（`IV || C` 一锅端）→ CBC 比特翻转 / Padding Oracle 直接打。
- **ECB 模式**：相同明文块产生相同密文块；可做 ECB 字典 / 块重排 / 字节逐位 oracle。
- 文件/响应头出现 **`Salted__`**（OpenSSL `enc -salt` 默认头）→ 密钥由 password+salt 经 KDF 派生，方向转向弱口令爆破或已知 KDF。
- DES/3DES：8 字节块；弱密钥（`0x0101010101010101` 等）、半弱密钥、ECB/CBC 下与 AES 同理的块攻击。
- 题目直接给 AES 算法但模式/填充/密钥来源可疑（KDF、固定 nonce、CTR 重用 nonce）。

## 核心攻击手法

### 1. Padding Oracle（CBC，PKCS#7）— 最经典
前提：oracle 对"padding 合法"与"padding 非法"返回可区分响应（报错/状态码/内容长度差）。
逐块从后往前，每字节 256 次试探恢复明文，**不需要密钥**。

```bash
# 一键自动化（推荐，省手搓）
pip install paddingoracle
python -c "
from paddingoracle import BadPaddingException, PaddingOracle
from requests import post
import base64

class P(PaddingOracle):
    def __init__(self, **kw): super().__init__(**kw); self.sess=0
    def oracle(self, data, **kw):
        # 把 前置块 + data(构造的上一块) + 目标块 拼成完整密文提交
        ct = base64.b64encode(self.iv + data + self.target).decode()
        r = post('http://TARGET/decrypt', data={'ct': ct})
        # 关键：根据实际响应判断 padding 是否合法
        if b'padding' in r.content: raise BadPaddingException
        return True
"
```

手动确认中间值公式（理解用）：构造 `C' = 0..0 || guess || padpad...`，使 `D(C_target)[i] XOR C'[i] == pad`。oracle 返回合法即命中。每块 16*256 上限请求。

### 2. CBC 比特翻转（Bit Flipping）
前提：知道明文结构（如 `user=guest;role=user`），想篡改成 `role=admin`。
原理：`P[i] = D(C[i]) XOR C[i-1]`，翻转 `C[i-1]` 的某字节，对应 `P[i]` 同字节翻转。

```python
# 已知 P 明文，想把 P 中 dst 处的字符改成 target
def flip_block(C_prev_byte, P_byte, dst_byte):
    return C_prev_byte ^ P_byte ^ dst_byte   # 替换密文前一块对应字节
# 注意：翻转会破坏前一块明文（变成乱码），把被破坏块放到不关心位置或重新 oracle 修复
```

### 3. ECB 字节字典 / 块重排
- **字节字典**：若服务把 `prefix || your_input || suffix` 用 ECB 加密且可逐字节对齐。固定 one-byte brute，比较块相等定位每个未知字节（典型题：`AES-ECB(secret)` oracle）。
- **块重排**：ECB 下交换密文块即交换明文块；可把 admin 块挪到前部。
- **ECB penguin**：图片加密用 ECB → 视觉仍可辨认，直接肉眼读 flag。

```python
# ECB 字节 oracle 骨架（block=16）
def recover_byte(prefix, known, blk_size=16):
    pad_len = blk_size - (len(prefix) + len(known)) % blk_size - 1
    base = prefix + 'A'*pad_len
    target_idx = len(base) // blk_size
    target = enc(base)[target_idx*blk_size:(target_idx+1)*blk_size]
    for g in range(256):
        ch = chr(g)
        probe = enc(base + known + ch)
        if probe[target_idx*blk_size:(target_idx+1)*blk_size] == target:
            return ch
```

### 4. CTR / 流密码 nonce 重用
两个密文用同一 (key, nonce) → `C1 XOR C2 = P1 XOR P2`，已知/猜出一份明文即恢复另一份（ crib dragging）。GCM 同理且 nonce 重用可恢复认证密钥 H。

```python
# C1 ^ C2 后做 crib-drag
import itertools
x = bytes(a^b for a,b in zip(C1, C2))
for guess in [b'flag{', b'CTF{', b'the ', b'http']:
    for i in range(len(x)-len(guess)+1):
        key = bytes(x[i+j]^guess[j] for j in range(len(guess)))
        # 用 key 滑动解另一段，看是否出可读英文
```

### 5. OpenSSL `Salted__` 头 → KDF / 弱口令
头：`Salted__`(8B) + salt(8B) + 密文。密钥/IV 由 password+salt 经 EVP_BytesToKey（MD5/SHA256）派生。

```bash
# 确认是 OpenSSL enc 格式
head -c 16 enc.bin | xxd            # 53616c7465645f5f = "Salted__"
# 已知口令直接解
openssl enc -d -aes-256-cbc -pbkdf2 -in enc.bin -pass pass:'GUESS'
# 口令未知 → rockyou 跑（批量脚本）
while read p; do
  openssl enc -d -aes-256-cbc -pbkdf2 -in enc.bin -pass pass:"$p" 2>/dev/null \
    | grep -aq flag && { echo "PW=$p"; break; }
done < rockyou.txt
```

### 6. DES 弱/半弱密钥、ECB 重放
- 弱密钥（`0x0101010101010101`、`0xFEFEFEFEFEFEFEFE` 等）下 `E_K(E_K(x)) == x`，即加密=解密，可构造等价明文。
- 3DES meet-in-the-middle：2TDEA 用两独立密钥时复杂度降到 ~2^57（理论向，CTF 多为弱配置直接给提示）。

## 工具命令
```bash
# 快速判断块大小 / 模式
python3 -c "import base64; d=base64.b64decode(open('ct.b64').read()); print(len(d), len(d)%16, len(d)%8)"
# paddingoracle 自动化（见上）
pip install paddingoracle
# PKCS#7 手搓块加解密 / 比特翻转辅助
python3 -c "from Crypto.Cipher import AES; print(AES.new(b'0'*16, AES.MODE_CBC, b'0'*16).encrypt(b'X'*16).hex())"
# OpenSSL 系列
openssl enc -d -aes-128-ecb -in ct.bin -K $(echo -n $KEY | xxd -p) -nopad
openssl enc -aes-256-cbc -pbkdf2 -salt -in pt -out ct -pass pass:SECRET
# crib-drag 流密码 nonce 重用
python3 cribdrag.py <(echo $C1XORC2HEX)   # github: froofIe/crib-drag 或 Keraghos/crib-drag
```

## 深度参考（穷尽技巧时加载）
- `/home/threed/.claude/skills/hack-skills-main/skills/symmetric-cipher-attacks/SKILL.md`
- `/home/threed/.claude/skills/hack-skills-main/skills/symmetric-cipher-attacks/BLOCK_CIPHER_ATTACKS.md`

## 关联 leaf
- `ctf-crypto-classical`：XOR 单字节/已知明文与流密码 nonce 重用同源，常串。
- `ctf-crypto`（二级路由）：白盒 AES / AES-ECB-CBC 进阶、RSA 等非本考点回二级分流。
- `ctf-web-` 系列不直接关联；但 Padding Oracle 常挂在 web 加密 cookie/会话接口上，链路为 web 接口 → 对称考点（如 cookie oracle = web 会话 + 本 leaf）。
