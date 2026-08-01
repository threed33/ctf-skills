---
name: ctf-misc
description: CTF Misc 杂项解题工作流（二级总纲：工作流骨架 + 三级 leaf 路由表 + 跨切面纪律）。触发词：CTF-misc、CTF 杂项、CTF 取证、CTF 隐写、pcap、forensics、stego。与 auto-pentest 并列，不互调流程。
---

# CTF Misc 解题工作流（二级总纲 / 薄 router）

> **定位**：CTF misc 方向（取证/隐写/编码谜题）二级总纲。本文件只保留三样——①工作流骨架 ②三级 leaf 路由表 ③跨切面纪律。
> **每漏洞细节知识（payload/工具用法）一律在三级 leaf**，不在本文件翻。
> 主 agent 自包含，**不依赖 vulnclaw**，纯工具链。
> **agent-agnostic** + **CTF 原则**（拿 flag 即止、不臆想、写解题链）。
> **不处理二进制/pwn/逆向**——遇此类标记"暂不支持，需 pwn/reverse 专项"。
> **与 auto-pentest 并列**：本 skill 只做 CTF 解题，不跑渗透六阶段流程，二者不互调。

## 三级 leaf 路由表

识别到该考点就调对应 leaf，**不在本文件翻细节**：

| 识别特征 | 调用 leaf |
|---|---|
| 隐写 / stego / LSB / 色道分离 / PNG 尺寸篡改 / 音频频谱 / 零宽字符 / SSTV / zsteg | `ctf-misc-stego` |
| 取证 / forensics / pcap / tshark / 内存 dump / volatility / 磁盘镜像 / foremost / USB 流量 / HTTP 对象导出 / DNS 隧道 | `ctf-misc-forensics` |
| 编码谜题 / esolang / Brainfuck / ook / jsfuck / 条码 / 二维码 / 多层嵌套 / 神秘字符串 | `ctf-misc-puzzle` |

> 路由原则：先 `file`/`strings` 粗判类型 → 命中上表某行 → 调对应 leaf 取 payload；类型不明时先停在侦察阶段，不要瞎猜漏洞类型。

## 跨切面纪律（硬约束）

1. **禁止对图片/二进制使用 Read 工具**：当前模型为**纯文本**（settings.json 全档位指向 glm-5-2-260617），任何 image content block 都会触发 `400 Model only support text input`。
   - **绝对禁止**对图片（PNG/JPG/JPEG/GIF/BMP/WebP/AVIF）或二进制文件（pcap/内存 dump/磁盘镜像/压缩包/可执行）调用 **Read 工具**——Read 会把图片转成 image 块塞回上下文，立即 400 中断整个流程。
2. **一律 Bash 跑命令行工具读文本输出**：`file` / `strings` / `xxd` / `binwalk` / `exiftool` / `zsteg` / `steghide` / `zbarimg` / `tesseract` / `tshark` / `vol`。需要"看图"时改用程序化方式产出文本（Pillow 脚本读像素/分通道、`tesseract` OCR、`zbarimg` 解码），绝不直接 Read。
3. **附件必须以纯文本路径给出**（如 `/mnt/c/.../x.png`）。若用户消息里出现 `[Image #N]`（内联附图），会在 skill 启动前就 400，此时无法恢复——提示用户"改为给出文件路径，不要拖/贴图片"。

## 阶段 0：就绪自检

| 依赖 | 自检命令 | 状态 |
|---|---|---|
| file/strings/xxd/binwalk/exiftool/hashcat | `which file strings binwalk exiftool hashcat` | ✅ 已装 |
| steghide/foremost/pngcheck/tshark | `which steghide foremost pngcheck tshark` | ❌ 待装(apt) |
| zsteg | `which zsteg` | ❌ 待装(**gem**，需 ruby；勿用 pip) |
| volatility | `/home/threed/ctf/venv/bin/vol -h` | ⚠️ 待装(pip volatility3) |
| Pillow | `/home/threed/ctf/venv/bin/python -c "import PIL"` | ⚠️ 待装 |

> 缺工具即停、问用户去装，不要自行源码编译绕过。

## 工具降级表

| 能力 | 首选 | 降级（首选不可用时） |
|---|---|---|
| PNG/BMP LSB 检测 | `zsteg -a` | Pillow 读像素位自写 LSB 提取 |
| PNG 完整性校验 | `pngcheck` | Pillow 读尺寸 + 手算 CRC |
| 色道分离 | stegsolve.jar | Pillow 分通道 `img.split()` |
| 二维码/条码 | `zbarimg` | 在线识别 |
| pcap 分析 | `tshark` | 在线工具 / scapy(venv) |

## 工作流阶段骨架

执行顺序，每题按此走：

1. **侦察 / 文件识别**：`file`（真实类型，勿信扩展名）→ `strings`/`xxd`（可读串、`tail -c 200` 末尾数据）→ `binwalk -e`（附加/嵌入文件）→ `exiftool`（元数据：GPS/注释/作者）→ 文件头尾 + CRC 校验。
2. **扫描 / 定性**：综合上一步输出判定考点类别（隐写？取证？编码谜题？类型不明？）。
3. **专项利用（router 动作）**：**识别漏洞类型 → 查上方「三级 leaf 路由表」→ 调对应 `ctf-misc-*` leaf，不在本文件堆 payload**。leaf 返回该考点的攻击步骤、工具命令、降级链。
4. **flag 提取与校验**：见下节。
5. **总结报告**：见下节。

## flag 提取与校验

1. **flag 格式校验**：`flag\{[^}]+\}` 或题目指定格式。
2. 多层解包未出 flag 则回阶段 1 重新识别类型，换 leaf 再试。

## 输出规则

| 规则 | 路径 |
|---|---|
| 总结报告 | `/home/threed/ctf/misc/solve_{题目名}.md` |
| 提取文件 | `/home/threed/ctf/misc/files/` |
| flag | `/home/threed/ctf/misc/flags.txt` |

> **AK 模式**（见 ctf-master）：比赛冲榜时跳过报告，拿到 flag 立即返回 `flag + 一句话解法 + 关键命令`，报告后置到 Phase 3。

## 总结报告模板引用

每题必写总结报告到 `/home/threed/ctf/misc/solve_{题目名}.md`，结构同 ctf-web（目标概况/考点清单/解题路径图/提取数据/flag 状态/解题思路链/工具链）。提取的中间文件存 `/home/threed/ctf/misc/files/`，flag 追加 `/home/threed/ctf/misc/flags.txt`。

## 使用方式

输入："附件是个 png，帮我找 flag" 或 "这个 pcap 文件分析下有没有 flag"。
**附件必须以纯文本路径给出，不要拖/贴图片进对话（`[Image #N]` 会在 skill 启动前触发 400）。**
触发后按阶段 0 → 工作流骨架执行，**每题必出总结报告**（AK 模式除外）。
