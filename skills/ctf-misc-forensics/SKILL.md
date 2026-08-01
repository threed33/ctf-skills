---
name: ctf-misc-forensics
description: CTF 取证 攻击 playbook。识别/触发：取证/forensics/pcap/tshark/内存dump/volatility/磁盘镜像/foremost/USB流量/HTTP对象导出/DNS隧道。碰到 .pcap/.pcapng 抓包、raw/mem 内存镜像、.img/.dd/.E01 磁盘镜像、题目给 USB HID 流量、HTTP 对象导出、DNS 查询长度异常/Iodine/DNSCat 隧道、文件头被抹/嵌入文件等指纹时，由二级 ctf-misc 路由表调用本 leaf，专项解决"这个取证考点怎么打"。
---

# CTF 取证 解题 playbook

> **定位**：CTF skill 树三级 leaf（知识锚点）。由二级 `ctf-misc` 路由表按识别特征调用；本文件只讲"这个考点怎么打"，不重复工作流。
> **CTF 原则**：拿 flag 即止、不写修复、不臆想、区分确认与推测。靶机常不出网 → 优先本地回显路径。

## 识别特征（什么时候调我）
- 题目附件 `.pcap` / `.pcapng` / `.cap`（Wireshark/tshark 抓包）
- 附件 `.raw` / `.mem` / `.vmem` / `.dmp` / `.lime`（内存镜像，上 volatility）
- 附件 `.img` / `.dd` / `.E01` / `.vmdk` / `.qcow2`（磁盘/虚拟机镜像，上 autopsy/ftk/TestDisk）
- pcap 里大量 USB interrupt URB（USB HID 键盘/鼠标流量）
- HTTP 流里能看到 GET/POST 文件、`Content-Type: application/octet-stream`（导对象）
- DNS 查询超长、子域名是 hex/base32、固定域名 TXT/A 记录高频（DNS 隧道，iodine/dnscat2）
- 文件头被改/`file` 识别不出/`binwalk` 报嵌入结构（文件 carving，foremost/binwalk）
- 题目给"已挂载"目录或 `.bash_history` / `.git` 残留（磁盘取证）

## 核心攻击手法

### 1. pcap 总览：先看协议分布、导对象、follow stream
```bash
# 协议层级分布，快速锁定主流量
tshark -r challenge.pcap -z io,phs -q | sort -t' ' -k1 -rn | head

# 导出所有 HTTP 传输对象（文件/图片/zip 常在这里）
tshark -r challenge.pcap --export-objects http,./http_out -q
tshark -r challenge.pcap --export-objects smb,./smb_out -q
tshark -r challenge.pcap --export-objects ftp-data,./ftp_out -q

# 按 TCP 流编号逐条 follow，找明文凭据/flag
tshark -r challenge.pcap -z follow,tcp,ascii,0 -q
tshark -r challenge.pcap -Y "tcp.stream" -T fields -e tcp.stream | sort -un   # 列所有流号

# 字符串里直接捞 flag/密码（最快签到）
strings -n 6 challenge.pcap | grep -iE 'flag|ctf|key|password='
```

### 2. USB HID 键盘/鼠标流量还原
```bash
# 先过滤 USB interrupt 包，看是不是 HID
tshark -r usb.pcap -Y 'usb.transfer_type==0x01 && usb.endpoint_address.direction==1' -T fields \
  -e usb.capdata | head

# 键盘：每帧 8 字节，第 3 字节是 HID keycode；逐字节解码
tshark -r usb.pcap -Y 'usb.capdata' -T fields -e usb.capdata | \
  awk -F: '{print $3}' | tr -d '\n' > keys.hex
# 把每两位 hex 映射到 HID keycode -> ASCII（用现成脚本 usbkeyboard.py / 对查表）
# 鼠标：第 3 字节按键(左=0x01 右=0x02)、第 4-5 字节 X/Y 偏移 → 累加成路径画图
```
HID keycode 查表（左 Ctrl/Shift/Alt 影响大小写，0x04=a 0x1e=1 ...，0x28=Enter，0x29=Esc，0x2c=Space）。

### 3. DNS 隧道（iodine / dnscat2）
```bash
# 子域名是 hex 或 base32、固定 base 域名高频查询 → 基本实锤隧道
tshark -r tunnel.pcap -Y 'dns.qry.name' -T fields -e dns.qry.name | sort | uniq -c | sort -rn | head

# 抽所有查询名，去掉 base 域名后拼接 → 解 base32/base64 出数据/flag
tshark -r tunnel.pcap -Y 'dns.qry.type==1' -T fields -e dns.qry.name | \
  awk -F. '{print $1}' | tr -d '.' | tr '\n' '' > dns.hex
# iodine 默认 base64(-+)，dnscat2 默认 hex；TXT 记录里常是上行数据
tshark -r tunnel.pcap -Y 'dns.txt' -T fields -e dns.txt | tr -d '"' | tr -d '\n'
```

### 4. 内存镜像（volatility3 / volatility2）
```bash
# 先识镜像 profile（vol3 自动，vol2 需 imagecopy+信息）
vol3 -f mem.raw windows.info.Info
vol3 -f mem.raw windows.pstree.Pstree            # 进程树，找可疑进程/父子关系
vol3 -f mem.raw windows.cmdline.CmdLine          # 进程命令行，挖恶意/解题脚本
vol3 -f mem.raw windows.netscan.NetScan          # 网络连接（不出网也能看到本地 socket）
vol3 -f mem.raw windows.filescan.FileScan | grep -iE 'flag|\.zip|\.txt|desktop'
vol3 -f mem.raw windows.dumpfiles --pid <PID> -D ./dump/    # 把可疑文件 dump 出来
vol3 -f mem.raw windows.hivelist.Hivelist        # 注册表 hive，配合 hashdump/lsadump
vol3 -f mem.raw windows.registry.hivelist.Hivelist
# Linux 镜像换 linux.* 插件，需对应 profile/symbol
```

### 5. 磁盘镜像 / 文件 carving
```bash
# 先挂载或用 autopsy；裸 carve 用 binwalk/foremost
file disk.img
binwalk -e disk.img                          # 自动识别并提取嵌入文件
foremost -v -i disk.img -o ./foremost_out    # 按 carving 规则分离 jpg/zip/pdf...
# 已删除文件/分区：TestDisk 修分区表，photorec 恢复文件
sudo losetup -Pf disk.img && sudo mount /dev/loop0p1 /mnt/disk   # -P 解析分区表
# 翻 .bash_history / .git/refs / 回收站 / 影子卷拷贝(VSS) / ADS 流
```

### 6. 文件头修复 / 杂项取证
```bash
file chall; xxd chall | head                  # 看真实 magic（PNG=89504e47, ZIP=504b0304, JPG=ffd8ff）
# header 被抹 → 用同类型正常文件头覆盖回前 N 字节
pngcheck -v chall.png                          # 校验 PNG CRC/IDAT，坏 CRC 常藏 flag
zip -FF chall.zip --out fixed.zip              # 修半损 zip
```

## CTF 实战结晶
（待积累，下次遇到本题型回填此处：题名 + 取证 trick + 关键命令 + 链路）

## 工具命令
```bash
# pcap
tshark -r c.pcap -T fields -e ip.src -e ip.dst | sort | uniq -c | sort -rn  # 高频端点定位
zeek -r c.pcap                                 # 生 conn.log/http.log/dns.log 结构化日志
strings -el c.pcap                             # -el = 16-bit little-endian，捞 UTF-16 明文

# 内存/磁盘
vol3 -f m.raw windows.malfind.Malfind         # 找注入/injected 内存区
bulk_extractor disk.img -o ./be/              # 自动抽邮箱/URL/信用卡/正则命中的串
strings -n 8 disk.img | grep -iE 'th4_|flag\{'  # 直接捞 flag 格式串

# 一站式：binwalk/foremost/strings/xxd/file 往往三步出结果，先这些再上重型工具
```

## 深度参考（穷尽技巧时加载）
- hack-skills-main/skills/traffic-analysis-pcap/SKILL.md
- hack-skills-main/skills/memory-forensics-volatility/SKILL.md

## 关联 leaf
- `ctf-misc-stego`：pcap 导出的图片/磁盘里藏的文件常转隐写（LSB、文件尾追加数据）
- `ctf-misc`：二级路由，处理文件分析、杂项签到
- `ctf-crypto`：DNS 隧道/USB 流量里常套一层编码或弱加密，取证 + 解码混用
