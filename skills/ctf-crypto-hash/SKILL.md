---
name: ctf-crypto-hash
description: CTF Hash 哈希 攻击 playbook。识别/触发：hash/md5/sha1/sha256/hashcat/crackstation/彩虹表/rainbow table/salt/哈希识别/hash-identifier/NTLM/bcrypt/scrypt/带盐哈希/哈希长度扩展/hash length extension/HMAC/Merkle-Damgard。碰到 32 位 hex、40 位 hex、64 位 hex、$1$/$2y$/$6$、`hashlib.md5(...)`、登录态 cookie 是哈希、签名校验 md5(secret+msg)、文件完整性校验值等指纹时，由二级 ctf-crypto 路由表调用本 leaf，专项解决"这个哈希考点怎么打"。
---

# CTF Hash 哈希 解题 playbook

> **定位**：CTF skill 树三级薄 leaf（知识锚点）。由二级 `ctf-crypto` 路由表调用；只讲"这个考点怎么打"。
> **CTF 原则**：拿 flag 即止、不写修复、不臆想、区分确认与推测。靶机常不出网 → 优先本地回显。

## 识别特征（什么时候调我）
- 固定长度 hex 串：32 位→MD5；40 位→SHA1；64 位→SHA256；128 位→SHA512。
- 代码出现 `hashlib.md5/sha1/sha256`、`crypto.createHash`、`openssl dgst`；登录 cookie/token 由哈希构成。
- `$1$salt$`(MD5 crypt)、`$2y$`(bcrypt)、`$6$`(SHA512 crypt)、`hash:salt` 两段式 → 带盐哈希。
- 签名校验 `md5(secret + message)` / `sha1(key + body)` → 哈希长度扩展候选。
- 文件校验/去重场景哈希可控 → 碰撞/二次扩展候选。

## 核心攻击手法

### 0. 哈希识别（先认算法再动手）
```bash
hashid '<hash>'            # 纯 Python，列所有候选
hash-identifier            # 交互式；$2y$/$6$/$1$ 直接由前缀判定
```

### 1. 无盐弱哈希 → 在线彩虹表 / 字典爆破
```bash
# 首选在线表（免算力秒杀常见口令）：crackstation.net / cmd5.com / hashes.com
hashcat -m 0    hash.txt rockyou.txt        # MD5
hashcat -m 100  hash.txt rockyou.txt        # SHA1
hashcat -m 1400 hash.txt rockyou.txt        # SHA256
hashcat -m 0    hash.txt -a 3 '?l?l?l?d?d?d' # 掩码：字母3+数字3
hashcat -m 0    hash.txt --show             # 复用 potfile 已破解结果
```

### 2. 带盐哈希 → hashcat salt 模式
```bash
hashcat -m 10  'hash:salt' rockyou.txt      # md5($pass.$salt)
hashcat -m 20  'hash:salt' rockyou.txt      # sha1($salt.$pass) 注意顺序
hashcat -m 320 'hash:salt' rockyou.txt      # bcrypt 慢→先窄字典
# bcrypt/scrypt/argon2 极慢：优先 cmd5/crackstation，字典用 rockyou-top1k
```

### 3. 哈希长度扩展攻击（md5/sha1/sha256 同理）
触发：服务端用 `md5(secret + msg)` 签名，能拿到原签名+原消息，secret 长度可枚举。
```python
pip install hashpumpy   # git: bwall/HashPump
import hashpumpy
for sklen in range(1, 41):
    new_sig, new_msg = hashpumpy.hashpump(SIG, "user=guest", "&user=admin", sklen)
    # 把 new_msg + new_sig 回送服务端，命中 flag/admin 即成功
```

### 4. MD5 碰撞（同前缀碰撞、绕文件 md5 去重/校验）
```bash
fastcoll -p prefix.bin -o a.out b.out   # 给定前缀生成一对 md5 相同的文件
# SHA-1 identical-prefix: shattered.io 公开实例
```

## CTF 实战结晶
（待积累，下次遇到本题型回填此处）

## 工具命令
```bash
hashid '<h>' ; hash-identifier
# 在线：crackstation.net / cmd5.com / hashes.com
# hashcat -m 码：0=MD5 100=SHA1 1400=SHA256 1700=SHA512
#              10=md5($p.$s) 20=sha1($s.$p) 320=bcrypt 1800=$6$ sha512crypt
hashcat -m <code> target.txt /usr/share/wordlists/rockyou.txt --show
pip install hashpumpy   # hashpumpy.hashpump(oldsig, oldmsg, append, keylen)
fastcoll -p prefix.bin -o a.out b.out
```

## 深度参考（穷尽技巧时加载）
- hack-skills-main/skills/hash-attack-techniques/SKILL.md
- https://github.com/bwall/HashPump （长度扩展）
- https://shattered.io/ （SHA-1 碰撞）
- hashcat example_hashes：https://hashcat.net/wiki/doku.php?id=example_hashes

## 关联 leaf
- `ctf-crypto`：哈希题总入口，路由到本 leaf。
- `ctf-web-sqli`：拖库拿哈希 → 本 leaf 爆破还原明文（dump → crack 链）。
- `ctf-web-jwt`/会话：登录态 cookie / JWT 弱密钥爆破常串成 web 登录链。
- `ctf-crypto-classical`：纯字母位移/异或不归本 leaf，去古典密码 leaf。
