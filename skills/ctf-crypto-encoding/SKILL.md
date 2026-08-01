---
name: ctf-crypto-encoding
description: CTF 编码识别与多层解码 攻击 playbook。识别/触发：编码识别/base64/base32/base16/hex/base85/urlencode/多层递归解码/编码套娃。碰到密文像 base 家族但不确定变体、&#xNN; HTML 实体、%XX URL 编码、反复套娃的 base64/base32/hex、需要逐层剥离直到出 flag 等指纹时，由二级 ctf-crypto 路由表调用本 leaf，专项解决"这个编码考点怎么打"。
---

# CTF 编码识别与多层解码 解题 playbook

> **定位**：CTF skill 树三级 leaf（知识锚点）。由二级 `ctf-crypto` 路由表按识别特征调用；本文件只讲"这个考点怎么打"，不重复工作流。
> **CTF 原则**：拿 flag 即止、不写修复、不臆想、区分确认与推测。编码题几乎全是本地回显，无 OOB 需求。

## 识别特征（什么时候调我）
- 密文全是 **大写字母 + 少量数字（2-7）**，末尾一串 `=` → Base32（Base64 含小写 + 0-9 + `/`，Base16 仅 0-9A-F）
- 密文 **A-Za-z0-9+/ **，末尾 0-2 个 `=` → Base64
- 密文 **纯 0-9a-fA-F**，长度偶数 → Base16/hex
- 密文里大量 `&#xNN;` 或 `&#NN;` → HTML 实体编码（十六进制 / 十进制字符引用）
- 密文里 `%XX`（`%41%42...`）→ URL 编码（urlencode）
- 解出一层后**仍是上述形态** → 编码套娃，递归再解
- 解出明文里出现 `[XXX_FLAG]` / `flag{...}` / 平台占位符 → 到底了

## 核心攻击手法

### 1. 字符集判断表（先认层，再解码）
| 编码 | 字符集 | 填充 | 长度/特征 |
|------|--------|------|-----------|
| Base16 (hex) | `0-9 A-F`（不区分大小写） | 无 | 长度必为偶数 |
| Base32 | `A-Z 2-7`（无 0/1/8/9/小写） | `=` 个数 ∈ {0,1,3,4,6} | 长度 8 的倍数 |
| Base64 | `A-Z a-z 0-9 + /` | `=` 个数 ∈ {0,1,2} | 长度 4 的倍数 |
| Base85 (ascii85/b85) | ASCII 33-117，可见乱字符 | 无 | 无填充；ascii85 常带 `~>` 包裹 |
| URL | 任意，`%XX` 转义非字母数字 | 无 | `%` 密集 |
| HTML 实体 | `&#xNN;` / `&#NN;` / `&lt;` | 无 | 分号结尾的小片段串 |

**关键判别**：Base64 **最多 2 个 `=`**；出现 3 个以上 `=` 直接判 Base32。Base32 字母表**不含 0/1/8/9**——密文里出现这些数字就不是 Base32。

### 2. 单层解码（Python 标准库，无需安装）
```python
import base64, html, urllib.parse
base64.b16decode('47445A43'.upper())          # hex -> bytes
base64.b32decode('JBSWY3DPEBZXK===')           # 长度须对齐到 8
base64.b64decode('U2VjcmV0')                   # 标准
base64.b85decode(b'...')                       # b85；ascii85 用 a85decode
html.unescape('&#x5b;&#x47;')                  # HTML 实体
urllib.parse.unquote('%41%42%43')              # URL
```

> 坑：Python `b32decode` 要求长度对齐到 8，缺 `=` 要自己补 `'=' * (-len(s) % 8)` 再解。

### 3. 自动递归解码脚本骨架（套娃题直接喂密文）
```python
import base64, re, html, urllib.parse
FLAG = re.compile(r'(flag|FLAG|CTF|GZCTF|MOECTF)\{[^}]+\}')

def detect(s):
    s = s.strip()
    if re.fullmatch(r'(?:&#x?[0-9a-fA-F]+;|&[a-zA-Z]+;)+', s):           return 'html'
    if '%' in s and re.search(r'%[0-9a-fA-F]{2}', s):                    return 'url'
    if re.fullmatch(r'[0-9a-fA-F]+', s) and len(s) % 2 == 0:             return 'hex'
    if re.fullmatch(r'[A-Z2-7]+=*', s) and len(s) % 8 in (0,2,4,5,7):    return 'b32'
    if re.fullmatch(r'[A-Za-z0-9+/]+=*', s):                             return 'b64'
    return None

def step(s):
    t = detect(s)
    try:
        if t == 'html': return html.unescape(s)
        if t == 'url':  return urllib.parse.unquote(s)
        if t == 'hex':  return bytes.fromhex(s).decode('latin1')
        if t == 'b32':  return base64.b32decode(s + '=' * (-len(s) % 8)).decode('latin1')
        if t == 'b64':  return base64.b64decode(s + '=' * (-len(s) % 4)).decode('latin1')
    except Exception:
        return None
    return None

def unwind(ct, depth=64):
    for i in range(depth):
        if FLAG.search(ct): return ct, i
        nxt = step(ct)
        if not nxt or nxt == ct: return ct, i          # 到底或卡住
        ct = nxt
    return ct, depth

if __name__ == '__main__':
    import sys
    out, n = unwind(open(sys.argv[1]).read().strip())
    print(f'[+] {n} 层后 -> {out}')
```

跑法：`python3 unwind.py challenge.txt`。出 `[XXX_FLAG]` 占位符说明题目部署时会替换，真实 flag 一般在附件 `challenge.txt` / `README.md` 里标注。

## CTF 实战结晶

### Not Only Base（GZCTF / TopSecCTF，crypto/编码）
- **密文**：`LNDVUQ2UIZPUMTCBI5OQ====`
- **trick**：靠字符集锁定 Base32——密文只有大写字母 + 数字 `2`/`5`（落在 2-7），**无小写、无 0/1/8/9、无 +/**，排除 Base64/Base16；末尾 **4 个 `=`**（Base64 最多 2 个）确认 Base32。
- **payload**：
```bash
python3 -c "import base64; print(base64.b32decode('LNDVUQ2UIZPUMTCBI5OQ====').decode())"
# [GZCTF_FLAG]
```
- **链路**：base32 一层到底 → `[GZCTF_FLAG]` 占位符 → 题目 challenge.txt 标注真实 flag。
- **flag**：`GZCTF{97d1fe1f}`（确认，附件标注）

### 多次编码（GZCTF / TopSecCTF，crypto/编码）
- **密文**：`&#x5b;&#x47;&#x5a;&#x43;&#x54;&#x46;&#x5f;&#x46;&#x4c;&#x41;&#x47;&#x5d;`
- **trick**：`&#xNN;` = HTML 十六进制字符引用，每个实体 = 一个字符的 ASCII 十六进制值（`&#x5b;`→0x5b→`[`）。
- **payload**：
```python
import html
ct = "&#x5b;&#x47;&#x5a;&#x43;&#x54;&#x46;&#x5f;&#x46;&#x4c;&#x41;&#x47;&#x5d;"
print(html.unescape(ct))   # [GZCTF_FLAG]
```
- **链路**：`html.unescape` 一层到底 → `[GZCTF_FLAG]`。
- **flag**：`GZCTF{9fae6a1b}`（确认，附件标注）

> **共同规律**：GZCTF/TopSecCTF 编码题常把明文先替换成 `[GZCTF_FLAG]` 占位符再编码，线上部署时替换为真 flag；解出占位符即视为解通，真 flag 在附件 README/challenge.txt 里给出。

## 工具命令
```bash
# 命令行快速单层
python3 -c "import base64;print(base64.b64decode('xxx'))"
python3 -c "import base64;print(base64.b32decode('XXX===='))"
python3 -c "import html,sys;print(html.unescape(open(sys.argv[1]).read()))" file.txt
echo '%41%42' | python3 -c "import sys,urllib.parse;print(urllib.parse.unquote(sys.stdin.read()))"

# 套娃递归（见上方脚本骨架）
python3 unwind.py challenge.txt

# CyberChef（本地无 Python 时，浏览器 "Magic" 自动识别 + 多层解码）
#   https://gchq.github.io/CyberChef/  → From Base / From Hex / From HTML Entity 反复堆
```

## 深度参考（穷尽技巧时加载）
- （本考点为 CTF 原生，无对应 hack-skills-main 深度参考；Python `base64` / `html` / `urllib` 标准库 + CyberChef 即穷尽主流 trick，保持自包含。）

## 关联 leaf
- `ctf-crypto-classical`：解完编码层后露出的若是古典密码（ROT/维吉尼亚/XOR/摩斯），转该 leaf。
- `ctf-crypto-hash`：解出的是 32/40/64 位 hex 哈希时，转该 leaf 爆破/查表。
- `ctf-crypto`（二级路由）：编码层常是 RSA/AES/古典密码题的"外壳"，剥离后按明文形态再分发。
