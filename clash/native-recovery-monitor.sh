#!/usr/bin/env bash
# Low-frequency native egress recovery monitor. No node probing.
# 2026-11-28: 生产专属组件收入 repo, 纳入 deploy-clash-suite.sh 管理 (原为 tebi 手工维护).
set -u
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY all_proxy
LOG=/personal/clash/native-recovery.log
LOCK=/tmp/native-recovery.lock
exec 9>"$LOCK"
flock -n 9 || exit 0
count=0
say(){ printf '%s %s\n' "$(date '+%F %T')" "$*" >> "$LOG"; }
say 'monitor started'
while true; do
  code=$(curl -q --max-time 8 -sS -o /dev/null -w '%{http_code}' https://cloudflare.com/cdn-cgi/trace 2>/dev/null || echo 000)
  say "direct_cf=$code"
  if [ "$code" = 200 ]; then
    count=$((count+1))
  else
    count=0
  fi
  if [ "$count" -ge 3 ]; then
    say 'native egress healthy; monitor exits'
    exit 0
  fi
  sleep 60 9>&-
done
