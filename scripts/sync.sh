#!/usr/bin/env bash
# sync.sh — 仓库与两侧加载路径（.claude / .reasonix）真身副本同步（copy 模式）。
#
# 用法：
#   sync.sh           默认 = pull：~/.claude/skills/ctf-* → 仓库 + ~/.reasonix
#                              （收口 Claude Code 工作副本到 canonical 仓库）
#   sync.sh push      仓库 → ~/.claude/skills + ~/.reasonix/skills（分发 / 重装）
#   sync.sh status    三方 diff 概览（哪边改了）
#
# 约定：canonical = 仓库（有 git 历史）。日常在 ~/.claude 改 skill 后跑 sync.sh 收口，
#       再 git add -A && git commit && git push。
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$REPO/skills"
CLAUDE="$HOME/.claude/skills"
REASONIX="$HOME/.reasonix/skills"
MODE="${1:-pull}"

cpclean() { # 用 $1 覆盖 $2：rm -rf "$2" && cp -r "$1" "$2"
  rm -rf "$2"; cp -r "$1" "$2"
}

case "$MODE" in
  pull)
    for d in "$CLAUDE"/ctf-*; do
      [ -e "$d" ] || continue
      n=$(basename "$d")
      cpclean "$d" "$SRC/$n"
      cpclean "$d" "$REASONIX/$n"
    done
    echo "pulled: ~/.claude/skills/ctf-* → 仓库 + ~/.reasonix/skills/"
    echo "  下一步: cd $REPO && git add -A && git commit -m '...' && git push"
    ;;
  push)
    for d in "$SRC"/ctf-*; do
      [ -d "$d" ] || continue
      n=$(basename "$d")
      cpclean "$d" "$CLAUDE/$n"
      cpclean "$d" "$REASONIX/$n"
    done
    echo "pushed: 仓库 → ~/.claude/skills + ~/.reasonix/skills"
    ;;
  status)
    changed=0
    for d in "$SRC"/ctf-*; do
      n=$(basename "$d")
      for dest in "$CLAUDE" "$REASONIX"; do
        if ! diff -q "$d/SKILL.md" "$dest/$n/SKILL.md" >/dev/null 2>&1; then
          printf 'DIFF  %-36s  %s 与仓库不一致\n' "$n" "$(basename "$(dirname "$dest")")"
          changed=1
        fi
      done
    done
    [ "$changed" -eq 0 ] && echo "三方一致，无差异"
    ;;
  *)
    echo "用法: sync.sh [pull|push|status]" >&2; exit 1 ;;
esac
