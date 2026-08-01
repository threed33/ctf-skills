#!/usr/bin/env bash
# verify-tree.sh — 校验 ctf skill 树完整性。
#   1. 仓库含 26 个 ctf-* 目录
#   2. ~/.claude/skills 与 ~/.reasonix/skills 各 26 个有效 symlink，指回仓库
#   3. master + 3 router 文档里引用的 ctf-* token 都在仓库中存在（路由表闭合）
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$REPO/skills"

fail=0
ok()  { printf '  \033[32m✓\033[0m %s\n' "$*"; }
bad() { printf '  \033[31m✗\033[0m %s\n' "$*"; fail=1; }
say() { printf '%s\n' "$*"; }

say "== 1. 仓库 leaf 清单 =="
n=$(ls -1d "$SRC"/ctf-* 2>/dev/null | wc -l | tr -d ' ')
[ "$n" -eq 26 ] && ok "仓库含 26 个 ctf-* 目录" || bad "仓库 ctf-* 数=$n（期望 26）"

say "== 2. 两侧 symlink 有效 =="
for dest in "$HOME/.claude/skills" "$HOME/.reasonix/skills"; do
  m=$(find "$dest"/ctf-* -maxdepth 0 -type l 2>/dev/null | wc -l | tr -d ' ')
  [ "$m" -eq 26 ] && ok "$dest: 26 个 symlink" || bad "$dest: symlink 数=$m（期望 26）"
  for l in "$dest"/ctf-*; do
    [ -L "$l" ] || continue
    if [ ! -f "$l/SKILL.md" ]; then bad "$l/SKILL.md 经 symlink 不可读"; fi
  done
done

say "== 3. 路由表引用闭合（master + 3 router 引用的 leaf 应都存在）=="
actual=$(ls -1d "$SRC"/ctf-* | xargs -n1 basename | sort -u)
for doc in ctf-master ctf-web ctf-crypto ctf-misc; do
  f="$SRC/$doc/SKILL.md"
  [ -f "$f" ] || { bad "缺 $f"; continue; }
  # 提取 ctf-<track>[-<vuln>] 形 token，去掉自身
  refs=$(grep -oE 'ctf-[a-z]+(-[a-z0-9]+)+' "$f" | sort -u | grep -vx "$doc" || true)
  for r in $refs; do
    echo "$actual" | grep -qxF "$r" || bad "$doc 引用 \`$r\` 但仓库无此目录"
  done
done
ok "路由表引用扫描完成（上面无 ✗ 即闭合）"

say ""
if [ "$fail" -eq 0 ]; then printf '\033[32mALL GREEN\033[0m\n'; exit 0; else printf '\033[31mHAS FAILURES\033[0m\n'; exit 1; fi
