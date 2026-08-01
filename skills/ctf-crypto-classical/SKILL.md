---
name: ctf-crypto-classical
description: CTF 古典密码 攻击 playbook。识别/触发指纹：古典密码/ROT/Caesar凯撒/凯撒移位/维吉尼亚/Vigenère/Vigenere/XOR/异或/替换密码/词频分析/频率分析/Morse/摩斯/培根/Bacon/ASCII移位/培根密码。碰到密文为纯字母位移、空格分隔整数、异或十六进制串、英文长文本无明显空格、滴答长短符号(. -)、AB五字节组等指纹时，由二级 ctf-crypto 路由表调用本 leaf，专项解决"这个古典考点怎么打"。
---

# CTF 古典密码 解题 playbook

> **定位**：CTF skill 树三级 leaf（知识锚点）。由二级 `ctf-crypto` 路由表按识别特征调用；本文件只讲"这个考点怎么打"，不重复工作流。
> **CTF 原则**：拿 flag 即止、不写修复、不臆想、区分确认与推测。古典题基本不出网，全是本地爆破/分析。

## 识别特征（什么时候调我）
- 密文是纯大写/小写字母串、无明显空格、英文 like → Caesar/ROT/替换/维吉尼亚
- 密文是空格分隔的整数（如 `96 76 95 72 ...`）→ **ASCII 移位变体凯撒**（见实战结晶）
- 密文是十六进制串且长度偶数、字符字节范围 → XOR（单/多字节）
- 长英文文本、保留空格、单字替换特征 → 替换密码，走词频分析
- 只有 `.` `-` `/` 空格、滴答长短 → Morse
- 只有 A/B 两个字符（或大小写二分）、5 字符一组 → 培根（Bacon，5 bit = 1 字母）
- 题面明示 ROT13/ROT47/Caesar/Vigenère/XOR 等关键词

## 核心攻击手法

### Caesar / ROT（字母表内移位）
```python
ct = "Khoor Zruog"  # 密文
for k in range(26):                       # 遍历 25 个偏移
    out = ""
    for c in ct:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            out += chr((ord(c) - base - k) % 26 + base)
        else:
            out += c
    print(k, out)                          # 找可读那行
```
- ROT47 处理所有可打印 ASCII（`!`~`~`，共 94 个）：`(ord(c)-33+47)%94+33`
- 偏移未知就遍历 25 次肉眼看可读；CTF 多为英文 flag，可对每个候选算英文 word 命中率自动判。

### ASCII 值移位凯撒（变体，高频考点）
不是字母表内移位，而是**直接对每个字符的 ASCII 码做 ±k**。密文常表现为空格分隔整数或偏移后的字符。
```python
ct = [96, 76, 95, 72, 89, 75, 100, 75, 81, 70, 76, 98]   # 空格分隔整数
for k in range(1, 256):                  # 偏移未知时暴破
    pt = "".join(chr((c - k) % 128) for c in ct)
    if pt.startswith("flag") or "CTF" in pt or "{" in pt:
        print(k, pt)
```

### 维吉尼亚 Vigenère（已知/未知密钥）
- 已知密钥：直接逆向 `pt = (c - key_i) mod 26`。
- 已知密钥长 L、未知密钥：把密文按 L 分组，每组建一个英文字母直方图，每列做单表凯撒（用英文字母频率 E/T/A/O/I 高频拟合），拼出密钥。
- 完全未知密钥长：Kasiski 测距（重复 3-gram 间距的 GCD）/ Friedman 重合指数估算 L，再按上一步。
- 工具优先：`pip install pycipher`，或在线 dcode.fr 的 Vigenère 自动爆破。

### XOR（单字节 / 多字节）
```python
# 单字节 XOR：256 暴破，按可打印率/英文词频挑
import re
hex_ct = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
raw = bytes.fromhex(hex_ct)
for k in range(256):
    pt = bytes(b ^ k for b in raw)
    if re.fullmatch(rb"[\x20-\x7e\n]+", pt) and b"flag" in pt.lower():
        print(k, pt)                       # 命中即 flag
```
- 多字节 XOR（Repeating-key XOR）：已知明文片段 → 直接 `key = ct[i]^pt[i]`；未知 → 用 `xortool`：`xortool -l <keylen> file.bin` 或先测密钥长（汉明距离归一化最小化，见 IC 法）。

### 替换密码（单表）
保留空格的长英文 → 词频分析：统计密文字母频率 → 对照英文 ETAOIN SHRDLU 排序映射；双字母/三字母高频 → TH/HE/IN/THE/AND。Python 手撸或用 quipqiup.com 自动求解。

### Morse / 培根
- Morse：`.` `-` 空格分隔，按国际码表还原；注意分隔符层级（字母间/单词间）。在线 dcode.fr/morse-code。
- 培根：每 5 个 A/B（或大小写、字体差异）一组 → 查 24 字母表（I/J、U/V 同字）。

## CTF 实战结晶
**题：凯撒加密（TopSecCTF / GZCTF 平台）**
- 考点：**ASCII 值移位凯撒变体**——不是字母表内移位，而是每个字符的 ASCII 值统一 +k。
- 附件 `challenge.txt` 给出空格分隔整数 + 提示密钥 = 5。
- 确切链路：密文 `[96,76,95,72,89,75,100,75,81,70,76,98]` → 每个数字 `-5` → `chr()` → `[GZCTF_FLAG]`（占位符）→ 真实 flag = **`GZCTF{05e9a1d0}`**。
- 关键脚本：
```python
ct = [96, 76, 95, 72, 89, 75, 100, 75, 81, 70, 76, 98]
key = 5
print("".join(chr(c - key) for c in ct))   # [GZCTF_FLAG]
```
- trick 收纳：看到空格分隔整数先认 ASCII 序列；密钥未给就 `for k in range(1,256)` 暴破挑可读；还原后若是 `[XXX_FLAG]` 形式，说明是平台占位符，真正 flag 在 challenge.txt 或题目元数据里。

## 工具命令
```bash
# Python 标准库即可覆盖 Caesar/ROT/ASCII移位/XOR 暴破，无需装包
python3 -c "ct=[96,76,95,72,89,75,100,75,81,70,76,98]; print(''.join(chr(c-5) for c in ct))"

# 多字节 XOR 分析（缺工具先问用户装，不要源码编译）
pip install xortool pycipher
xortool -l 0 -x file.bin            # 自动测密钥长 + 爆破

# 在线兜底（CTF 常用，靶机不涉网）：dcode.fr 覆盖 Caesar/ROT/Vigenère/Morse/Bacon/替换
```

## 深度参考（穷尽技巧时加载）
- hack-skills-main/skills/classical-cipher-analysis/SKILL.md
- dcode.fr 工具箱（在线，覆盖几乎所有古典密码自动识别 + 爆破）

## 关联 leaf
- `ctf-crypto`：本 leaf 的二级路由表，遇非古典（RSA/AES/padding oracle/编解码 base 系列）回到路由表。
- 常见串链：古典密码还原出的明文常是另一个题的"flag"或提示下一段（如 XOR 解出 base64 → 再解出 RSA 参数 → 进 `ctf-crypto-rsa` 类 leaf）。
