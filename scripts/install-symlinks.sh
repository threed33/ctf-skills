#!/usr/bin/env bash
# install-symlinks.sh — 把本仓库 skills/ctf-* 安装为两侧加载路径下的 symlink。
#
# 目标路径：
#   ~/.claude/skills/ctf-*      （Claude Code canonical 加载路径）
#   ~/.reasonix/skills/ctf-*    （reasonix 镜像）
#
# 幂等：已是正确 symlink 则跳过；存在旧真身/副本/错误链接则备份为 .bak.<ts> 再建。
# 单一源——编辑仓库内文件，两侧即时生效。
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$REPO/skills"
TARGETS=("$HOME/.claude/skills" "$HOME/.reasonix/skills")

if [ ! -d "$SRC" ]; then
  echo "ERROR: 仓库 skills/ 不存在: $SRC" >&2
  exit 1
fi

ts=$(date +%Y%m%d%H%M%S)
installed=0; backed_up=0; skipped=0

for dest in "${TARGETS[@]}"; do
  mkdir -p "$dest"
  for skill in "$SRC"/ctf-*; do
    [ -d "$skill" ] || continue
    name=$(basename "$skill")
    link="$dest/$name"
    if [ -L "$link" ] && [ "$(readlink -f "$link")" = "$(readlink -f "$skill")" ]; then
      skipped=$((skipped+1))          # 已是正确 symlink
      continue
    fi
    if [ -e "$link" ] || [ -L "$link" ]; then
      mv "$link" "$link.bak.$ts"      # 备份旧真身 / 错误 symlink
      backed_up=$((backed_up+1))
    fi
    ln -s "$skill" "$link"
    installed=$((installed+1))
  done
done

echo "install-symlinks: new=$installed  backed_up=$backed_up  already_ok=$skipped"
echo "  source : $SRC"
echo "  targets: ${TARGETS[*]}"
[ "$backed_up" -gt 0 ] && echo "  （旧文件已备份为 *.bak.$ts，确认无误后可删）"
