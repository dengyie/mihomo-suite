#!/usr/bin/env bash
# Mac 侧 /personal/clash 配置快照 (rsync 镜像 + 按天保留)
#
# 为什么: /personal 是 pxed+tebi 共享 NFS, 2026-11-26 pxed 已退役后只剩 tebi 一个
# 挂载方 + 一份活数据。NAS 配额事故 (2026-11-20 config.yaml 被截断成 0 字节) 说明
# 单副本会静默损坏, 而 /data 快照只在 tebi 本机。Mac 定期把整目录镜像到本地,
# 提供 host 之外的第三份拷贝。
#
# 用法: scripts/snapshot-personal-clash.sh [--retention-days 14]
# launchd: ~/Library/LaunchAgents/com.mango.personal-clash-snapshot.plist (每小时)

set -euo pipefail

RETENTION_DAYS=14
[ "${1:-}" = "--retention-days" ] && { RETENTION_DAYS=${2:-14}; shift 2; }

HOST=${SNAPSHOT_HOST:-tebi}
REMOTE=${SNAPSHOT_REMOTE:-/personal/clash}
DEST="$HOME/.local/share/tebi-clash-snapshot"
LOG="${DEST}/snapshot.log"

mkdir -p "$DEST"

say() { printf '%s %s\n' "$(date '+%F %T')" "$*" | tee -a "$LOG"; }

# 锁: launchd 触发 + 手动跑可能重叠, overlap 的 rsync 会互相拖慢。
# macOS 无 flock(1), 用 mkdir 原子性 + pid 存活检查 (stale 锁自动清理)。
LOCK_DIR="$DEST/.snapshot.lock"
if mkdir "$LOCK_DIR" 2>/dev/null; then
  echo "$$" > "$LOCK_DIR/pid"
  trap 'rm -rf "$LOCK_DIR"' EXIT
else
  lock_pid=$(cat "$LOCK_DIR/pid" 2>/dev/null || echo "")
  if [ -n "$lock_pid" ] && ! kill -0 "$lock_pid" 2>/dev/null; then
    say "清理 stale 锁 (pid $lock_pid 已死)"
    rm -rf "$LOCK_DIR"
    mkdir "$LOCK_DIR" && echo "$$" > "$LOCK_DIR/pid" && trap 'rm -rf "$LOCK_DIR"' EXIT
  else
    say "另一个快照在跑, 跳过"
    exit 0
  fi
fi

say "=== rsync $HOST:$REMOTE -> $DEST (retention ${RETENTION_DAYS}d) ==="
# --delete 镜像语义; --exclude 掉运行态大文件 (cache.db 是 mihomo 本机 tmp 的
# 悬空 symlink 自愈源, 镜像它没有意义还可能带悬空链接)
rsync -az --delete \
  --exclude 'cache.db' --exclude 'cache.db.*' \
  --exclude 'mihomo.log*' --exclude '*.log' \
  --exclude '.nfs*' --exclude 'core' \
  -e "ssh -o BatchMode=yes -o ConnectTimeout=15" \
  "$HOST:$REMOTE/" "$DEST/data/"

rc=$?
if [ "$rc" -eq 0 ]; then
  say "rsync OK ($(du -sh "$DEST/data" 2>/dev/null | cut -f1) on disk)"
else
  say "WARN rsync rc=$rc (tebi 不可达或 NFS 抖动, 下轮重试)"
  exit "$rc"
fi

# 保留最近 N 天的日志
find "$DEST" -name 'snapshot.log.*' -mtime +"$RETENTION_DAYS" -delete 2>/dev/null || true
# 日志本身瘦身: 超过 2MB 截尾
if [ -f "$LOG" ]; then
  sz=$(stat -f %z "$LOG" 2>/dev/null || echo 0)
  if [ "$sz" -gt $((2 * 1048576)) ]; then
    tail -c 524288 "$LOG" > "$LOG.tmp" && mv "$LOG.tmp" "$LOG"
  fi
fi
