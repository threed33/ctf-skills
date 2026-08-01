#!/usr/bin/env bash
# verify-tree.sh — 校验 ctf skill 树完整性（copy 模式）。
#   1. 仓库含 26 个 ctf-* 目录
#   2. ~/.claude/skills 与 ~/.reasonix/skills 各 26 个真身目录（非 symlink）
#   3. 两侧每个 SKILL.md 与仓库 diff 一致（三方同步）
#   4. master + 3 router 文档引用的 ctf-* token 都存在（路由表闭合）
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

say "== 2. 两侧真身目录（type d，非 symlink）=="
for dest in "$HOME/.claude/skills" "$HOME/.reasonix/skills"; do
  d=$(find "$dest"/ctf-* -maxdepth 0 -type d 2>/dev/null | wc -l | tr -d ' ')
  l=$(find "$dest"/ctf-* -maxdepth 0 -type l 2>/dev/null | wc -l | tr -d ' ')
  if [ "$d" -eq 26 ] && [ "$l" -eq 0 ]; then ok "$dest: 26 真身目录，无 symlink"
  else bad "$dest: 真身=$d symlink=$l（期望 26/0）"; fi
done

say "== 3. 三方内容一致（每个 SKILL.md 与仓库 diff）=="
mismatch=0
for d in "$SRC"/ctf-*; do
  n=$(basename "$d")
  for dest in "$HOME/.claude/skills" "$HOME/.reasonix/skills"; do
    if ! diff -q "$d/SKILL.md" "$dest/$n/SKILL.md" >/dev/null 2>&1; then
      bad "$n ($dest) 与仓库不一致（跑 sync.sh 修复）"; mismatch=$((mismatch+1))
    fi
  done
done
[ "$mismatch" -eq 0 ] && ok "三方 26×2 处 SKILL.md 全部一致"

say "== 4. 路由表引用闭合（master + 3 router）=="
actual=$(ls -1d "$SRC"/ctf-* | xargs -n1 basename | sort -u)
for doc in ctf-master ctf-web ctf-crypto ctf-misc; do
  f="$SRC/$doc/SKILL.md"
  [ -f "$f" ] || { bad "缺 $f"; continue; }
  refs=$(grep -oE 'ctf-[a-z]+(-[a-z0-9]+)+' "$f" | sort -u | grep -vx "$doc" || true)
  for r in $refs; do
    echo "$actual" | grep -qxF "$r" || bad "$doc 引用 \`$r\` 但仓库无此目录"
  done
done
ok "路由表引用扫描完成（上面无 ✗ 即闭合）"

say ""
if [ "$fail" -eq 0 ]; then printf '\033[32mALL GREEN\033[0m\n'; exit 0; else printf '\033[31mHAS FAILURES\033[0m\n'; exit 1; fi
