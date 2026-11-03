#!/usr/bin/env bash
# tebi clash 常驻守护 (supervisord 托管, 见 /etc/supervisor/conf.d/clash-keeper.conf)
#
# 为什么需要: start-clash.sh 只在启动那一刻自检一次。mihomo 被 OOM/误杀后没人拉起,
# listener.proxy 指向的美国节点中途挂掉后没人换, 日志和 health 备份会无界增长。
# 本脚本把这三件事变成周期性的。
#
# 注意 /personal 是 pxed+tebi 共享 NFS, 本脚本只应由 host 本地的 supervisor conf 启动,
# 不要写进共享的 bootstrap 里, 否则两台机会同时改同一份 config。
set -u

DIR=/personal/clash
BIN="$DIR/mihomo"
LOG="$DIR/mihomo.log"
GUARD="$DIR/hutao-bridge-guard.py"
START="$DIR/start-clash.sh"

INTERVAL=${INTERVAL:-120}      # 自检间隔秒
LOG_MAX_MB=${LOG_MAX_MB:-50}   # mihomo.log 超过就瘦身
LOG_KEEP_MB=${LOG_KEEP_MB:-10} # 瘦身后保留末尾
BAK_RETAIN=${BAK_RETAIN:-20}   # 每族备份保留份数
GUARD_LOG_MAX_MB=${GUARD_LOG_MAX_MB:-5}

# mihomo 自身出站不能走容器坏代理
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY all_proxy ALL_PROXY

say() { echo "$(date '+%F %T') $*"; }

# 单实例: 两份同时跑会同时改同一份 config, 互相覆盖。
# 用 flock 而不是 pidfile: 锁由内核绑在 fd 上, 进程无论怎么死(含 SIGKILL)锁都自动释放,
# 不存在"陈旧 pidfile"。曾用 pidfile + kill -0, 被 SIGKILL 后 pidfile 残留, 一旦那个
# pid 被别的进程复用, keeper 每次启动都秒退 0; 而 startsecs=5 会把秒退判成启动失败,
# 重试 3 次后 supervisor 标 FATAL —— 守护进程永久躺平, 且没人会注意到。
# 阻塞式 flock: 拿不到锁就等着(进程活着, 能过 startsecs), 对方退出后自然接班。
#
# 注意子进程会继承 fd 9, 也就跟着持锁。父进程被 SIGKILL 后, 孤儿 sleep 会把锁
# 一直攥到自己睡醒 (最长 INTERVAL 秒), 接班者只能干等, 这段时间没人守护。
# 所以所有长跑子命令都显式 9>&- 关掉这个 fd。
LOCK=/tmp/clash-keeper.lock
exec 9>"$LOCK" || { say "无法打开锁文件 $LOCK"; exit 1; }
if ! flock -n 9; then
  say "另一个 keeper 持锁, 阻塞等待接班 (不秒退, 避免被判启动失败)"
  flock 9
fi
say "已持锁 pid=$$"

trap 'say "keeper 收到信号, 退出"; exit 0' TERM INT

# 原地截断保 inode。NFS 上 cp+mv 会让 mihomo 继续写被改名的旧 inode,
# 生成 .nfsXXXX 幽灵文件, 磁盘一直涨而 tail 看不到新日志 (踩过)。
shrink_in_place() {
  local f=$1 max=$2 keep=$3 mb
  [ -f "$f" ] || return 0
  mb=$(( $(stat -c %s "$f") / 1048576 ))
  [ "$mb" -gt "$max" ] || return 0
  local tmp="$f.shrink.$$"
  if tail -c "$(( keep * 1048576 ))" "$f" > "$tmp" 2>/dev/null; then
    cat "$tmp" > "$f" && say "瘦身 $(basename "$f"): ${mb}MB -> ${keep}MB"
  fi
  rm -f "$tmp"
}

# 备份轮转。写备份的不只 health-filter:
#   probe_clash_nodes.py -> .pre-health-*      (每轮 2 份, 曾累积 1300+ 份 / 343MB)
#   hutao-bridge-guard.py -> .pre-guard-*      (每次自愈 2 份, 节点抖动时会持续涨)
#   还有历史的 .pre-subimport- / .pre-listener- 等
# 所以按"族"通配, 而不是只清 health 一族。族 = 去掉尾部时间戳后的前缀。
prune_backups() {
  local base fam n
  for base in config.yaml config.mac-merged.yaml; do
    # 列出该 base 下所有备份族前缀 (.pre-health- / .pre-guard- / ...)
    for fam in $(ls -1 "$DIR/$base".pre-* 2>/dev/null \
                 | sed -E 's/[-_][0-9]{8}[-_T]?[0-9]{6}Z?$//' | sort -u); do
      n=$(ls -1dt "$fam"* 2>/dev/null | wc -l)
      [ "$n" -gt "$BAK_RETAIN" ] || continue
      ls -1dt "$fam"* 2>/dev/null | tail -n +$((BAK_RETAIN + 1)) | while read -r f; do
        # 二次确认: 只删带 .pre-<族>-<时间戳> 的文件, 绝不碰活配置
        case "$f" in
          "$DIR/config.yaml"|"$DIR/config.mac-merged.yaml") ;;
          *.pre-*) rm -f "$f" ;;
        esac
      done
      say "prune $(basename "$fam") $n -> $BAK_RETAIN"
    done
  done
}

# 跑子命令并把输出缩进转发; 关键是拿到子命令自己的 rc。
# 曾写成 "$GUARD" | sed ... || say WARN, 但管道的 rc 是 sed 的(永远 0),
# guard 失败被静默吞掉, 日志里只看到正常输出。
run_logged() {
  local label=$1; shift
  local out rc
  # 9>&- : 不让子进程继承锁 fd, 否则父进程被 SIGKILL 后子进程仍攥着锁
  out=$("$@" 2>&1 9>&-); rc=$?
  [ -n "$out" ] && printf '%s\n' "$out" | sed 's/^/  /'
  [ "$rc" -eq 0 ] || say "WARN $label rc=$rc"
  return "$rc"
}

say "=== clash-keeper 启动 interval=${INTERVAL}s ==="

while true; do
  # 精准检测主 Mihomo (7897/9090) 是否存活，不能用 pgrep -x 误判
  if ! netstat -ltn 2>/dev/null | grep -q ':7897 '; then
    say "mihomo 不在, 拉起"
    run_logged start-clash bash "$START" || true
  elif [ -x "$GUARD" ]; then
    # 单次自检: listener.proxy 悬空 / 桥不通 时换个活的美国节点并 reload
    run_logged guard "$GUARD" || true
  fi

  # PROXY Selector 自检: pin 死节点连续 2 轮失败自动切回 AUTO (2026-10-22 EOF 事故根修)
  if [ -x "$DIR/proxy-selector-guard.py" ]; then
    run_logged proxy-selector "$DIR/proxy-selector-guard.py" || true
  fi

  if [ -x "$DIR/apply-local-import.py" ]; then
    run_logged local-import "$DIR/apply-local-import.py" || true
  fi

  if [ -x "$DIR/rules-reconciler.py" ]; then
    run_logged rules-reconcile "$DIR/rules-reconciler.py" --reconcile || true
  fi

  if [ -x "$DIR/native-recovery-monitor.sh" ] && ! pgrep -f "[n]ative-recovery-monitor.sh" >/dev/null 2>&1; then
    run_logged native-monitor setsid "$DIR/native-recovery-monitor.sh" || true
  fi

  shrink_in_place "$LOG" "$LOG_MAX_MB" "$LOG_KEEP_MB"
  shrink_in_place "$DIR/hutao-bridge-guard.log" "$GUARD_LOG_MAX_MB" 1
  prune_backups

  # 同理关掉 fd 9: sleep 是这里最长命的子进程, 孤儿化后最能拖延接班
  sleep "$INTERVAL" 9>&-
done
