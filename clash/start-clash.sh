#!/usr/bin/env bash
# tebi mihomo 翻墙代理 一键启动 (幂等)
# 2026-11-28: 生产专属组件收入 repo, 纳入 deploy-clash-suite.sh 管理 (原为 tebi 手工维护, repo 无副本).
# 本机无公网入口/无 systemd, Pod 重建后 / 全丢, 本脚本与内核/配置均落 /personal 故可存活.
# 用法: bash /personal/clash/start-clash.sh
set -u
DIR=/personal/clash
BIN="$DIR/mihomo"
CFG="$DIR/config.yaml"
LOG="$DIR/mihomo.log"
LOG_MAX_MB=50
LOG_KEEP_MB=10

# 必须先绕开容器坏代理 ga.dp.tech:8118, 否则 mihomo 自身出站被劫持
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY all_proxy ALL_PROXY

# 清掉任何已有实例, 避免端口冲突产生空转进程
# 精准清理占用 7897 / 9090 的主 mihomo 实例，严禁 broad-kill pkill -x 误杀 CPA 10808
python3 -c "
import os, signal, subprocess
try:
    out = subprocess.check_output(['netstat', '-ltnp']).decode()
    for line in out.splitlines():
        if ':7897 ' in line or ':9090 ' in line:
            parts = line.split()
            if '/' in parts[-1]:
                pid = parts[-1].split('/')[0]
                if pid.isdigit() and int(pid) != os.getpid():
                    os.kill(int(pid), signal.SIGTERM)
except Exception:
    pass
" 2>/dev/null && sleep 1

# netstat -p 对 mihomo 拿不到 pid(显示"-"), 上面 python 块可能杀不掉旧实例; 兜底按进程名+cmdline 精确 TERM
for P in $(pgrep -x mihomo 2>/dev/null); do
  case "$(tr '\0' ' ' < /proc/$P/cmdline 2>/dev/null)" in
    */personal/clash/mihomo*) kill -TERM "$P" 2>/dev/null && echo "TERM 旧 mihomo pid=$P" ;;
  esac
done
sleep 1

# cache.db 悬空 symlink 自愈: Pod 重建会清空 /tmp/mnt, /personal/clash/cache.db ->
# /tmp/mnt/clash/cache.db 成悬空链(mihomo 能起但选中态静默丢)。此时先建目录并从
# NFS 上最新 retired 副本恢复,保住迁移前最后的组选中态。
if [ -L "$DIR/cache.db" ] && [ ! -e "$DIR/cache.db" ]; then
  mkdir -p /tmp/mnt/clash
  SRC=$(ls -t "$DIR"/cache.db.nfs-retired-* "$DIR"/cache.db.pre-local-migrate-* 2>/dev/null | head -1)
  if [ -n "$SRC" ]; then
    cp -a "$SRC" /tmp/mnt/clash/cache.db
    echo "cache.db 悬空自愈: 从 $SRC 恢复到 /tmp/mnt/clash/cache.db"
  else
    : > /tmp/mnt/clash/cache.db
    echo "cache.db 悬空且无 NFS 副本可恢复, 已新建空库(选中态回 config 默认)"
  fi
  chmod 600 /tmp/mnt/clash/cache.db
fi

# 2026-11-20 NAS 配额事故保险: config.yaml 被配额写失败截断成 0 字节时
# (mihomo 重启会读到空配置全灭), 从 /data 快照自动回填——/data 无配额限制。
if [ ! -s "$CFG" ]; then
  SNAP="/data/clash-config-live.yaml"
  if [ -s "$SNAP" ]; then
    if cat "$SNAP" > "$CFG" 2>/dev/null && [ -s "$CFG" ]; then
      echo "config.yaml 空文件自愈: 从 $SNAP 回填 $(wc -c < "$CFG") 字节"
    else
      echo "FATAL: config.yaml 为空且回填失败(配额?), 手动执行: cat $SNAP > $CFG"
    fi
  fi
fi

# 日志瘦身。必须原地截断(cat > 保 inode): NFS 上用 cp+mv 换掉文件会让仍持有 fd 的
# 进程继续写进 .nfsXXXX 幽灵 inode —— 日志看着停了, 空间还在涨。此处已 pkill, 但
# 仍坚持原地写法, 以防将来有人把这段挪到 mihomo 存活时执行。
if [ -f "$LOG" ]; then
  sz_mb=$(( $(wc -c < "$LOG") / 1048576 ))
  if [ "$sz_mb" -gt "$LOG_MAX_MB" ]; then
    tmp="$LOG.rotate.$$"
    if tail -c "$(( LOG_KEEP_MB * 1048576 ))" "$LOG" > "$tmp" 2>/dev/null; then
      cat "$tmp" > "$LOG" && echo "日志已瘦身: ${sz_mb}MB -> ${LOG_KEEP_MB}MB"
    fi
    rm -f "$tmp"
  fi
fi

# 脱离 SSH 会话常驻 (setsid + stdin<null, 否则会话结束被 SIGHUP 带走)
# 日志追加写 $LOG(不丢 /dev/null),便于切换/重启后排障。加时间戳分隔。
echo "===== $(date '+%F %T') start-clash.sh 重启 =====" >> "$LOG"
setsid "$BIN" -d "$DIR" >>"$LOG" 2>&1 < /dev/null &

# 等监听就绪
for i in $(seq 1 10); do
  sleep 1
  if netstat -tln 2>/dev/null | grep -q ':7897 '; then
    echo "mihomo up. mixed-port=7897 api=9090"
    # 胡桃美国出口桥自检 (listener.proxy 悬空引用 / 节点挂掉时自愈)
    if [ -x "$DIR/hutao-bridge-guard.py" ]; then
      "$DIR/hutao-bridge-guard.py" || echo "WARN: guard failed rc=$?"
    fi
    echo "代理用法: export https_proxy=http://127.0.0.1:7897 http_proxy=http://127.0.0.1:7897"
    echo "curl 记得加 -q 禁用坏代理 .curlrc: curl -q -x http://127.0.0.1:7897 ..."
    exit 0
  fi
done
echo "启动失败, 看日志: tail $LOG"
tail -5 "$LOG"
exit 1
