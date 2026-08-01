#!/usr/bin/env bash
# install.sh — 把仓库 skills/ctf-* 拷贝为两侧加载路径下的真身副本（copy 模式，非 symlink）。
# 用于：新机器 clone 后、pull 新内容后、或修复不一致。
# 注意：会覆盖两侧已有副本——若有未收口的本地改动，先跑 sync.sh 收口到仓库。
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$REPO/skills"
TARGETS=("$HOME/.claude/skills" "$HOME/.reasonix/skills")

[ -d "$SRC" ] || { echo "ERROR: 仓库 skills/ 不存在: $SRC" >&2; exit 1; }

for dest in "${TARGETS[@]}"; do
  mkdir -p "$dest"
  for skill in "$SRC"/ctf-*; do
    [ -d "$skill" ] || continue
    n=$(basename "$skill")
    rm -rf "$dest/$n"
    cp -r "$skill" "$dest/$n"
  done
done
echo "installed (copy): $(ls -1d "$SRC"/ctf-* | wc -l | tr -d ' ') skills → ${TARGETS[*]}"
