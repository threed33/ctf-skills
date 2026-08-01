---
name: ctf-misc-puzzle
description: CTF 编码谜题/esolang 攻击 playbook。识别/触发：编码谜题/esolang/Brainfuck/ook/jsfuck/条码/二维码/多层嵌套/神秘字符串。碰到大量 `+-<>[].,`、`ook. ook! ook?` 串、全是 `[]()!+` 的 jsfuck、(Brainfuck 变体) Whitespace/Malbolge/Piet、ASCII 子集编码、Base 系列多层嵌套、二维码/条码图片、看似乱码的神秘字符串等指纹时，由二级 ctf-misc 路由表调用本 leaf，专项解决"这个编码/谜题考点怎么打"。
---

# CTF 编码谜题/esolang 解题 playbook

> **定位**：CTF skill 树三级 leaf（知识锚点）。由二级 `ctf-misc` 路由表按识别特征调用；本文件只讲"这个考点怎么打"，不重复工作流。
> **CTF 原则**：拿 flag 即止、不写修复、不臆想、区分确认与推测。纯编码/esolang 题 100% 本地解，不涉及靶机交互。

## 识别特征（什么时候调我）
- 串全是 `+-<>[].,` 八种字符 → **Brainfuck**（或其变体 Ook!/Blub/Brainloller）。
- 串全是 `ook.` / `ook!` / `ook?` 三种 token → **Ook!**（Brainfuck 等价语义）。
- 串只有 `[]()!+` → **JSFuck**（浏览器里 eval 即 JS）；类似的有 JJencode/AAencode。
- 串看似空白（空格/TAB/换行）但题目给文本文件 → **Whitespace**（空格=0、TAB=1、LF=结束标记的栈式 VM）。
- 串是十六进制 / Base32 / Base64 / Base85 / Base91 / Base62，且解码后又是一层编码 → **多层嵌套**（递归套娃，典型 3–7 层）。
- 长串大写字母+数字，末尾 `=` 或 `==`，或全可见 ASCII 但解码后非明文 → 先丢 **CyberChef / dcode.fr** 自动识别。
- 图片含方形点阵二维码 / 一维条码（EAN/Code39/Code128） → **扫码题**（常配破损/缺失定位点需修复）。
- 串里反复出现 `CTF`、`flag` 但被位移/异或/倒序 → 结合 ctf-crypto-classical 处理。
- 题目文案直接点名 "esolang"、"编程语言"、"only 8 commands"、"the title is a hint" → 几乎必是 esolang。

## 核心攻击手法

### 1. Brainfuck / Ook! 直接解释执行
```bash
# pip 装解释器
pip install brainfuck 2>/dev/null
# 在线或本地：直接跑
python3 -c "import brainfuck; brainfuck.evaluate(open('bf.txt').read())"
```
```python
# 自带解释器（无需依赖），处理 Brainfuck 及 Ook!/Blub（先转回 +-<>[].,）
def bf(code, src=''):
    code = ''.join(c for c in code if c in '+-<>[].,')
    tape=[0]*30000; ptr=i=0; out=[]; src=iter(src)
    while i < len(code):
        c=code[i]
        if c=='>':ptr+=1
        elif c=='<':ptr-=1
        elif c=='+':tape[ptr]=(tape[ptr]+1)%256
        elif c=='-':tape[ptr]=(tape[ptr]-1)%256
        elif c=='.':out.append(chr(tape[ptr]))
        elif c==',':tape[ptr]=ord(next(src,'\0'))
        elif c=='[':
            if not tape[ptr]:
                depth=1
                while depth: i+=1; depth+=(code[i]=='[')-(code[i]==']')
        elif c==']':
            if tape[ptr]:
                depth=1
                while depth: i-=1; depth+=(code[i]==']')-(code[i]=='[')
        i+=1
    print(''.join(out))
```

### 2. JSFuck 直接 eval
```javascript
// 浏览器 console 或 node 里直接跑（JSFuck 本身就是合法 JS）
eval(copy_the_jsfuck_string_here)
```

### 3. Whitespace 解释
```bash
# 在线：https://vyznev.net/whitespace/
# 本地：
git clone https://github.com/wspace/whitespace-tools  # 或用 wsc interp
# 注意把全角空格 / NBSP 也视为合法 token（常见坑）
```

### 4. 多层嵌套 Base 自动递归解码（万能起手式）
```python
import base64, binascii, re
def try_decode(b):
    for name, fn in [
        ("b64", lambda x: base64.b64decode(x+ b'='*(-len(x)%4))),
        ("b32", lambda x: base64.b32decode(x.upper()+ b'='*(-len(x)%8))),
        ("b85", base64.b85decode),
        ("a85", base64.a85decode),
        ("hex", binascii.unhexlify),
        # Base91 / Base62 需第三方库：pip install base91 base62
    ]:
        try:
            r = fn(b)
            if all(32 <= c < 127 or c in (9,10,13) for c in r):
                return name, r
        except Exception:
            pass
    return None, None

data = open("blob.bin","rb").read().strip()
for depth in range(20):
    print(depth, repr(data[:80]))
    if b'flag' in data or b'CTF' in data:
        print(">>> FOUND:", data); break
    name, r = try_decode(data)
    if name is None:
        print("stuck at depth", depth); break
    data = r
    print("  decoded via", name)
```

### 5. 二维码 / 条码识别（破损图先修复）
```bash
pip install pyzbar pillow qrcode
# 扫码
python3 -c "from pyzbar.pyzbar import decode; from PIL import Image; print([d.data.decode() for d in decode(Image.open('qr.png'))])"
# zbarimg（CLI 更稳）
zbarimg qr.png
# 噪声/反色/倒置 → PIL 先处理：img.point(lambda p: 255-p) 或 resize 放大
# 一维条码：zbarimg 同样识别 Code39/Code128/EAN13
```

### 6. 神秘字符串指纹判定（先识别再打）
```bash
# 在线首选：CyberChef "Magic" / dcode.fr 自动识别
# 本地：hash-identifier 不适用于编码；用 magic-trick 离线版
pip install magic-trick  # 或用 CyberChef 的 Node 版做 Magic
# 常见可自动命中：Base 系、ROT13、Atbash、Morse、Tap code、Braille 盲文、Dancing men、公式 A1Z26（a=1..z=26）
```

## CTF 实战结晶
（待积累，下次遇到本题型回填此处：题名 + 编码层数/类型 + 关键 trick + payload）

## 工具命令
```bash
# 一把梭在线工具（优先级最高，能省 90% 时间）
#   CyberChef:  https://gchq.github.io/CyberChef/  （Magic + From Base64 递归）
#   dcode.fr:   https://www.dcode.fr/   （esolang 全家桶 + 古典全收录）
#   Boxentriq:  https://www.boxentriq.com/code-breaking  （异或/栅栏/特征识别）

pip install brainfuck pyzbar pillow qrcode base91 base62
zbarimg qr.png                  # 二维码/条码 CLI
python3 bf_interp.py < bf.txt   # Brainfuck 自带解释器（见上文）
eval "$(pbpaste)"               # JSFuck 直接 JS 引擎里 eval
```

## 深度参考（穷尽技巧时加载）
- （本考点为 CTF 原生，无对应 hack-skills-main 深度参考；保持自包含即可）
- esolang 全集：https://esolangs.org/wiki/Language_list （含 Malbolge/Piet/Befunge/Unlambda 等冷门语种解释器线索）

## 关联 leaf
- `ctf-crypto-classical`：嵌套到最内层是 ROT/凯撒/维吉尼亚/异或 → 交古典 leaf。
- `ctf-crypto-hash`：神秘串实为哈希（hex 长度命中 32/40/64） → 交哈希 leaf。
- `ctf-misc-stego`（如存在）：二维码/条码藏于图片隐写层 → 先 stego 提取再回本 leaf 解码。
- `ctf-misc-forensics`（如存在）：pcap/磁盘里抠出编码串 → 先取证提取再回本 leaf。
```
