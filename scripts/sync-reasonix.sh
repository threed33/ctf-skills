#!/usr/bin/env bash
# sync-reasonix.sh — 同步 reasonix 侧 ctf-*。
#
# 历史上 reasonix 是 .claude 的 cp 副本，靠手动 cp 同步（会漂移）。
# 现已统一为「指向本仓库的 symlink」，与 .claude 同源——同步即重跑 install。
# 本脚本保留旧命令名以兼容肌肉记忆，实际等价于 install-symlinks.sh。
set -euo pipefail
exec "$(dirname "${BASH_SOURCE[0]}")/install-symlinks.sh" "$@"
