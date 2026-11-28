#!/usr/bin/env bash
# Mac 侧 tebi clash 链路健康检查 (poll /healthz, 连续 N 次失败才告警)
#
# 为什么 Mac 侧要探: tebi 自身 /healthz 只反映本机组件; 但 Mac 是真实客户端,
# "Mac 能不能经 10.144.144.32:2053 打到网关" 这条 mesh 链路只有 Mac 能验。
# gateway 已部署无认证 GET /healthz (status ok|degraded + components)。
#
# 告警通道: One-Mail API (agently-mail skill 的部署), 凭据复用
# ~/.config/agent-fleet/onemail-sender.json (origin + token, agentfleet 地址)。
# 抑制: 连续 3 次失败才发; 恢复后发一封 recovery; 告警间隔不小于 ALERT_COOLDOWN_SEC。
#
# 用法: scripts/tebi-health-check.sh [--once] [--alert-email you@example.com]
#   环境变量: TEBI_HEALTHZ_URL  TEBI_ALERT_EMAIL  ALERT_COOLDOWN_SEC
# launchd: ~/Library/LaunchAgents/com.mango.tebi-health-check.plist (每 5 分钟)

set -u

BASE_URL=${TEBI_HEALTHZ_URL:-http://10.144.144.32:2053/healthz}
FAIL_THRESHOLD=3
ALERT_COOLDOWN_SEC=${ALERT_COOLDOWN_SEC:-3600}
STATE_DIR="$HOME/.local/share/tebi-health-check"
STATE_FILE="$STATE_DIR/state"
LOG="$STATE_DIR/check.log"
CRED_FILE="$HOME/.config/agent-fleet/onemail-sender.json"

mkdir -p "$STATE_DIR"

# 参数解析
ALERT_EMAIL=${TEBI_ALERT_EMAIL:-}
ONCE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --alert-email) ALERT_EMAIL=${2:-}; shift 2 ;;
    --once) ONCE=1; shift ;;
    *) shift ;;
  esac
done

say() { printf '%s %s\n' "$(date '+%F %T')" "$*" | tee -a "$LOG"; }

read_state() { cat "$STATE_FILE" 2>/dev/null || echo "0 ok 0"; }

write_state() { printf '%s\n' "$*" > "$STATE_FILE"; }

send_alert_mail() {  # $1=subject  $2=body
  [ -n "$ALERT_EMAIL" ] || { say "未配置告警邮箱 (--alert-email), 只记日志: $1"; return 0; }
  [ -f "$CRED_FILE" ] || { say "无 One-Mail 凭据 $CRED_FILE, 只记日志: $1"; return 0; }
  python3 - "$1" "$2" "$ALERT_EMAIL" <<'PYEOF'
import json, sys, urllib.request
from pathlib import Path

subject, body, to_mail = sys.argv[1], sys.argv[2], sys.argv[3]
cred = json.loads(Path.home().joinpath('.config/agent-fleet/onemail-sender.json').read_text())
req = urllib.request.Request(
    cred['origin'].rstrip('/') + '/api/send_mail',
    data=json.dumps({
        'from_name': 'tebi-watch',
        'to_mail': to_mail,
        'to_name': '',
        'subject': subject,
        'content': body,
        'is_html': False,
    }).encode(),
    method='POST',
    headers={'Authorization': 'Bearer ' + cred['token'], 'Content-Type': 'application/json'},
)
try:
    with urllib.request.urlopen(req, timeout=15) as resp:
        print('alert mail status', resp.status)
except Exception as e:
    print('alert mail failed:', e)
PYEOF
}

# --- 探测 ---
http_code=$(curl -s -o "$STATE_DIR/last-body.json" -w '%{http_code}' \
  --max-time 10 --connect-timeout 5 "$BASE_URL" 2>/dev/null || echo 000)

if [ "$http_code" = "200" ]; then
  status=$(python3 -c "
import json
try:
    print(json.load(open('$STATE_DIR/last-body.json')).get('status', 'unknown'))
except Exception:
    print('unknown')
" 2>/dev/null || echo unknown)
else
  status="unreachable($http_code)"
fi

# --- 状态机: state 文件三列 = fails last_status last_alert_epoch ---
read -r fails prev_status last_alert <<EOF
$(read_state)
EOF

if [ "$status" = "ok" ] || [ "$status" = "degraded" ]; then
  if [ "${fails:-0}" -ge "$FAIL_THRESHOLD" ]; then
    say "RECOVERY: $BASE_URL 恢复 (status=$status, 之前连续失败 $fails 次)"
    send_alert_mail "tebi clash RECOVERY" \
      "tebi clash 网关恢复响应。url=$BASE_URL status=$status (degraded 表示有组件异常, 看 components 字段)。"
  fi
  write_state "0 $status 0"
  exit 0
fi

fails=$(( ${fails:-0} + 1 ))
now=$(date +%s)
write_state "$fails $status ${last_alert:-0}"
say "FAIL $fails/$FAIL_THRESHOLD: $status"

if [ "$fails" -ge "$FAIL_THRESHOLD" ]; then
  if [ $((now - ${last_alert:-0})) -ge "$ALERT_COOLDOWN_SEC" ]; then
    body="tebi clash 网关连续 $fails 次探测失败。
url: $BASE_URL
last status: $status
host: $(hostname -s)
time: $(date '+%F %T')

排查: ssh tebi 'supervisorctl status; tail /personal/clash/keeper.log'"
    say "告警: 连续 $fails 次失败 (status=$status)"
    send_alert_mail "tebi clash DOWN ($status)" "$body"
    write_state "$fails $status $now"
  else
    say "告警冷却中, 不重复发送"
  fi
fi
exit 1
