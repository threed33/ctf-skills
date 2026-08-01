---
name: ctf-misc-stego
description: CTF 隐写 stego 攻击 playbook。识别/触发指纹：隐写/stego/LSB最低有效位/steghide/steghide extract/stegseek/色道分离/通道分离/PNG尺寸篡改/改高度宽度/IHDR CRC校验/文件头修复/音频频谱/频谱图/Sonic Visualiser/Audacity/零宽字符/zero-width/SSTV/慢扫描电视/zsteg。碰到图片加宽出乱码、PNG CRC 报错、给一张看似正常的 png/jpg/bmp/gif/wav/png、附件只有图片无文本、strings 文件见 flag 伪影、色道末端藏 bits 等场景时，由二级 ctf-misc 路由表调用本 leaf，专项解决"这个隐写考点怎么打"。
---

# CTF 隐写 解题 playbook

> **定位**：CTF skill 树三级 leaf（知识锚点）。由二级 `ctf-misc` 路由表按识别特征调用；本文件只讲"这个考点怎么打"，不重复工作流。
> **CTF 原则**：拿 flag 即止、不写修复、不臆想、区分确认与推测。靶机常不出网 → 隐写基本是离线静态分析，无回连问题。

## 识别特征（什么时候调我）
- 题目只给一张图片（png/jpg/bmp/gif）或一个音频（wav/mp3/flac），无显式任务说明 → 先按隐写走。
- `file`/`xxd` 看文件头：扩展名与真实类型不符（如 png 后缀实为 zip、或 IHDR 异常）→ 文件头/尺寸篡改。
- PNG 打开报错 "CRC error in IHDR" / 高度宽度字段被改 → IHDR 尺寸篡改，藏了下半图。
- `strings` / `binwalk` 见尾部追加 zip/rar/7z 或伪影字符串 → 附加文件 / 多文件拼接。
- `zsteg` 命中 LSB 低位通道有可读文本/bit → PNG/BMP LSB 隐写。
- 题目名/描述含 "不可见字符"、"零宽"、"zero-width" → 零宽字符隐写（ZWSP/ZWJ/ZWNJ）。
- 音频 wav/mp3 + 题面暗示"听"、"频率"、"奇怪噪音" → 频谱图隐写 / SSTV / 摩斯 / DTMF。
- jpg 图片 + 给了 passphrase 提示 / `steghide` 字样 → steghide 隐写。

## 核心攻击手法

### 0. 一上来必做的全套侦察（先跑这套再分流）
```
file flag.png                       # 真实类型
xxd flag.png | head                 # 文件头 magic
binwalk -e flag.png                 # 扫附加/嵌入文件并自动提取
strings -n 6 flag.png | ctfgrep     # 可读串/flag 伪影
exiftool flag.png                   # 元数据 hint、Comment、作者字段常藏 flag
foremost -i flag.png -o out         # binwalk 提不动的备用 carve
```

### 1. PNG IHDR 尺寸篡改（改高度藏下半图）
IHDR 第 16-19 字节 = 宽（4B BE），第 20-23 字节 = 高。改高还原后，CRC（第 29-32 字节）对不上 → 工具报 CRC error 即实锤。
```
# python3: 暴力枚举正确宽高，按 CRC 校验通过判定真实值
python3 - <<'PY'
import struct, zlib
d = open('flag.png','rb').read()
ihdr = d[12:29]  # length(4)+type(4)+data(13)
w,h = struct.unpack('>II', d[16:24])
crc = struct.unpack('>I', d[29:33])[0]
for H in range(1, 4096):
    if zlib.crc32(d[12:29].replace(struct.pack('>I',h),struct.pack('>I',H))) & 0xffffffff == crc:
        print('real height =', H); break
# 写回正确高度
d2 = d[:20]+struct.pack('>I',H)+d[24:]
open('fix.png','wb').write(d2)
PY
```

### 2. PNG/BMP LSB（最低有效位）— zsteg 一把梭
```
zsteg flag.png                      # 自动试 b1/r,g,b/rgb/lsb 各通道
zsteg -a flag.png                   # 全通道全位深穷举
zsteg -e 'b1,rgb,lsb,xy' flag.png   # 指定通道提取到文件
# 或用 PIL 手写提取 R 通道最低位拼字节
```

### 3. steghide（jpg/wav，需 passphrase）
```
steghide extract -sf flag.jpg -p ""          # 空密码常中
steghide extract -sf flag.jpg -p "password"  # 题面给的口令
steghide info  flag.jpg -p ""                # 看藏了什么不提取
# 不知道口令 → stegseek 字典爆破（比 stegcracker 快几个数量级）
stegseek --crack flag.jpg /usr/share/wordlists/rockyou.txt
stegseek --seed flag.jpg                     # 纯暴力 seed 模式
```

### 4. 色道/通道分离（GIF 多帧、PNG 单通道藏图）
```
# ImageMagick 分离 R/G/B 三通道为灰度图，肉眼找异常通道
convert flag.png -channel R -separate r.png
convert flag.png -channel G -separate g.png
convert flag.png -channel B -separate b.png
# GIF 拆帧
convert flag.gif -coalesce frame_%02d.png
# 取帧间差异（帧叠加藏信息）
convert frame_00.png frame_01.png -compose difference -composite diff.png
```

### 5. 音频频谱 / SSTV / 摩斯
```
# Audacity / Sonic Visualiser 打开 wav，切频谱图（Spectrogram）视图
#   - 横向条纹文字 → 频谱图隐写（常见）
#   - 斜纹/机械图案 → SSTV 慢扫描电视，用 qsstv 还原图片
# 命令行频谱导出
sox flag.wav -n spectrogram -o spec.png
# SSTV 解码（需 GUI / 特定模式）
qsstv                # 选 Robot36/Scottie 等模式，播放 wav 还原图片
# 摩斯/DTMF
multimon-ng -t wav -a morse flag.wav
multimon-ng -t wav -a DTMF flag.wav
```

### 6. 零宽字符（zero-width）
```
# 把可疑文本存进 zw.txt，用工具解码（ZWSP U+200B / ZWNJ U+200C / ZWJ U+200D / LRM 等）
python3 - <<'PY'
t = open('zw.txt','r',encoding('utf-8')).read()
mp = {'​':0,'‌':1}      # 常见映射，按题调整
bits=''.join(str(mp[c]) for c in t if c in mp)
print(''.join(chr(int(bits[i:i+8],2)) for i in range(0,len(bits),8)))
PY
# 在线工具：stegano.cn / unicode-cloudflare 等
```

### 7. 文件头修复 / 多文件拼接
```
# PNG 标准头 89 50 4E 47 0D 0A 1A 0A；JPG FF D8 FF；GIF 47 49 46 38
# 文件头被抹/改 → 用 dd 或 hex 编辑器写回正确 magic 再打开
printf '\x89PNG\r\n\x1a\n' | dd of=flag.png bs=1 count=8 conv=notrunc
# 尾部追加的 zip：binwalk -e 提取，或 dd carve
dd if=flag.png of=tails.zip bs=1 skip=<binwalk 给的 offset>
unzip tails.zip
```

## CTF 实战结晶
（待积累，下次遇到本题型回填此处：题名 + 确切 trick + payload + 链路）

## 工具命令
```
# 一键环境（apt + pip，venv 隔离）
sudo apt install -y steghide binwalk foremost exiftool sonic-visualiser sox multimon-ng
python3 -m venv ~/.venv/stego && source ~/.venv/stego/bin/activate
pip install pillow stegano
# zsteg 是 ruby，单独装
sudo gem install zsteg
# stegseek（steghide 爆破，比 stegcracker 快）
sudo apt install stegseek        # 或从 github release 拖 deb
# 字典
ls /usr/share/wordlists/rockyou.txt
```

## 深度参考（穷尽技巧时加载）
- hack-skills-main/skills/steganography-techniques/SKILL.md

## 关联 leaf
- `ctf-misc`（二级路由：隐写与取证/pcap 并列分流）
- `ctf-misc-forensics`（ pcap / 内存 / 磁盘取证，常与隐写图片同场出现）
- `ctf-crypto-classical`（频谱/零宽解出的比特串常需再过一层古典或编码）
