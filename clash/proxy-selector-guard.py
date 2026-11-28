#!/opt/mamba/bin/python3
"""mihomo PROXY Selector 自检/自愈

2026-11-28: 生产专属组件收入 repo, 纳入 deploy-clash-suite.sh 管理.

背景: MangoApi (apihub) 全部上游请求走 HTTPS_PROXY=127.0.0.1:7897 → mihomo。
2026-10-22 PROXY 组被手动 pin 在死节点 [tomorin] CH BRN Buyvm (connection refused),
全站上游 EOF, 无任何告警——hutao-bridge-guard 只盯 10818 桥, 不管 PROXY 组。

本脚本: PROXY 组 pin 在具体节点且测活失败时, 自动切回 AUTO (URLTest) 并记录。
AUTO 本身有 URLTest 自愈, 无需干预。

用法:
  proxy-selector-guard.py            # 自检 + 必要时自愈 (写日志)
  proxy-selector-guard.py --check    # 只自检, 不自愈 (退出码表状态)

退出码: 0 健康  1 已自愈(pin 死节点→AUTO)  2 端到端探测失败  3 API 异常
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path

import yaml

CLASH_DIR = Path("/personal/clash")
CFG = CLASH_DIR / "config.yaml"
SECRET_FILE = CLASH_DIR / ".controller-secret"
LOG = CLASH_DIR / "proxy-selector-guard.log"
API = "http://127.0.0.1:9090"
GROUP = "PROXY"
AUTO = "AUTO"
# 端到端探测: 过 7897 真实出口
EGRESS_PROBE_URL = "http://www.gstatic.com/generate_204"
PROBE_TIMEOUT_MS = 5000
# pin 节点连续失败 N 次才动手 (跨多轮 guard 周期, 单次网络抖动不触发)
FAIL_THRESHOLD = 2
STATE_FILE = CLASH_DIR / ".proxy-selector-guard.state"


def log(msg: str) -> None:
    stamp = datetime.now().strftime("%F %T")
    line = f"{stamp} {msg}"
    print(line, flush=True)
    try:
        with LOG.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except OSError:
        pass


def secret() -> str:
    if SECRET_FILE.is_file():
        return SECRET_FILE.read_text(encoding="utf-8").strip()
    data = yaml.safe_load(CFG.read_text(encoding="utf-8"))
    return str(data.get("secret") or "")


def api(path: str, method: str = "GET", body=None, timeout: int = 20):
    req = urllib.request.Request(
        API + path,
        data=body,
        method=method,
        headers={"Authorization": "Bearer " + secret(), "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read()
        return resp.status, (json.loads(raw) if raw else None)


def node_delay(name: str) -> int | None:
    q = urllib.parse.quote(name, safe="")
    path = f"/proxies/{q}/delay?timeout={PROBE_TIMEOUT_MS}&url={urllib.parse.quote(EGRESS_PROBE_URL, safe='')}"
    try:
        _, obj = api(path, timeout=PROBE_TIMEOUT_MS // 1000 + 5)
        if obj and "delay" in obj:
            return int(obj["delay"])
    except Exception:
        pass
    return None


def egress_ok() -> bool:
    r = subprocess.run(
        ["curl", "-qsS", "-o", "/dev/null", "-w", "%{http_code}",
         "-x", "http://127.0.0.1:7897", "--max-time", "12", EGRESS_PROBE_URL],
        capture_output=True, text=True,
    )
    return r.stdout.strip() == "204"


def read_state() -> int:
    try:
        return int(STATE_FILE.read_text().strip())
    except Exception:
        return 0


def write_state(n: int) -> None:
    try:
        STATE_FILE.write_text(str(n))
    except OSError:
        pass


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()

    try:
        _, grp = api(f"/proxies/{GROUP}")
    except Exception as e:
        log(f"API error: {e}")
        return 3
    now = grp.get("now", "")
    all_nodes = grp.get("all", [])
    if now == AUTO or now not in all_nodes:
        # AUTO 或组中套组: 组自身有自愈, 只做端到端确认
        ok = egress_ok()
        if not ok:
            log(f"WARN now={now} egress probe failed")
            return 2
        write_state(0)
        return 0

    # pin 在具体节点: 实测延迟
    d = node_delay(now)
    fails = read_state()
    if d is not None:
        if fails:
            write_state(0)
        log(f"OK pinned={now} delay={d}ms")
        return 0

    fails += 1
    write_state(fails)
    log(f"FAIL pinned={now} delay-test failed ({fails}/{FAIL_THRESHOLD})")
    if args.check:
        return 2
    if fails < FAIL_THRESHOLD:
        return 2
    # 自愈: 切回 AUTO
    body = json.dumps({"name": AUTO}).encode()
    try:
        api(f"/proxies/{GROUP}", method="PUT", body=body)
    except Exception as e:
        log(f"ERROR switch to AUTO failed: {e}")
        return 3
    time.sleep(2)
    try:
        _, grp2 = api(f"/proxies/{GROUP}")
        healed = grp2.get("now") == AUTO and egress_ok()
    except Exception as e:
        log(f"ERROR verify after switch failed: {e}")
        return 3
    write_state(0)
    log(f"HEALED pin={now} dead -> PROXY=AUTO, egress_ok={healed}")
    return 1 if healed else 2


if __name__ == "__main__":
    sys.exit(main())
