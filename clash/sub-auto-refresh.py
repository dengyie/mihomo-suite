#!/opt/mamba/bin/python3
"""订阅自动刷新 (服务端兜底, keeper loop 每轮调起)

背景 (2026-11-28 hutao 事故): 机场上游轮换入口端点 (balancer.cedarblanket.com
→ lb.download.strawberrymemo.com) 后, 本地缓存的节点字段停留在旧端点,
TCP 可达但 anytls 会话全 503; 之前刷新只靠人工跑 --update, 没有任何
服务端周期机制, 缓存落后上游一轮就整池静默死亡。

本脚本把刷新做在服务端:
  - 每次被 keeper 调起时读 subscriptions/meta.json, 只有「距上次成功刷新
    >= SUB_AUTO_REFRESH_INTERVAL_HOURS (默认 6h)」的 remote 订阅才真正
    fetch + probe + inject + prune (复用 SubscriptionEngine.update_subscription
    的全部护栏: 上游删除清理、self_published 防环、dialer-proxy overlay 保留)。
  - 失败按 SUB_AUTO_REFRESH_FAILURE_RETRY_HOURS (默认 1h) 退避, 不锤上游。
  - 有任一订阅刷新成功后调 publish_client_clash_config(fetch_remote=False):
    客户端导出按输入指纹判断, 指纹变了才重渲染 + mihomo -t 校验后原子替换
    last-good。客户端 (Clash Verge) 下次轮询 /sub/clash 自动拿到新端点,
    不依赖任何客户端侧刷新逻辑。
  - raw 订阅 (无 url) 与 self_published (订阅自家发布站) 天然跳过。

用法:
  sub-auto-refresh.py            # 常规轮询: 只刷新到期的
  sub-auto-refresh.py --force    # 忽略到期/退避, 立即刷新所有符合条件的
  sub-auto-refresh.py --status   # 只打印到期状态, 不刷新

退出码: 0 无错误 (含"没到期的常规轮")  1 有订阅刷新失败
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))

from importlib.util import spec_from_file_location, module_from_spec

_sm_path = Path(__file__).resolve().parent / "subscription-manager.py"
_sm_spec = spec_from_file_location("subscription_manager", _sm_path)
_sm = module_from_spec(_sm_spec)
_sm_spec.loader.exec_module(_sm)
ROOT = _sm.ROOT  # noqa: E402
SubscriptionEngine = _sm.SubscriptionEngine  # noqa: E402

STATE_FILE = ROOT / 'subscriptions' / 'auto-refresh-state.json'
DEFAULT_INTERVAL_HOURS = 6.0
DEFAULT_FAILURE_RETRY_HOURS = 1.0


def _hours(env: str, default: float) -> float:
    try:
        v = float(os.environ.get(env) or '')
        return v if v > 0 else default
    except ValueError:
        return default


INTERVAL_HOURS = _hours('SUB_AUTO_REFRESH_INTERVAL_HOURS', DEFAULT_INTERVAL_HOURS)
FAILURE_RETRY_HOURS = _hours('SUB_AUTO_REFRESH_FAILURE_RETRY_HOURS', DEFAULT_FAILURE_RETRY_HOURS)
ONLY_IDS = {
    s.strip() for s in (os.environ.get('SUB_AUTO_REFRESH_IDS') or '').split(',') if s.strip()
}


def _parse_iso(value: Any) -> Optional[datetime]:
    try:
        return datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None


def load_state() -> Dict[str, Dict[str, Any]]:
    try:
        data = json.loads(STATE_FILE.read_text(encoding='utf-8'))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_state(state: Dict[str, Dict[str, Any]]) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = STATE_FILE.with_suffix(STATE_FILE.suffix + '.tmp')
    tmp.write_text(json.dumps(state, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    tmp.replace(STATE_FILE)


def refreshable(sub: Dict[str, Any]) -> bool:
    """自动刷新的准入: enabled + remote + 有 url + 非自家发布站。"""
    if not sub.get('enabled'):
        return False
    if sub.get('type') == 'raw' or sub.get('raw_content'):
        return False
    if sub.get('self_published'):
        return False
    return bool(sub.get('url'))


def due_hours(sub: Dict[str, Any], entry: Dict[str, Any]) -> float:
    """该订阅距下次刷新的小时数 (负数 = 已到期)。失败条目按退避间隔算。"""
    if entry.get('last_success'):
        anchor = _parse_iso(entry.get('last_success'))
        interval = INTERVAL_HOURS
    else:
        anchor = _parse_iso(entry.get('last_attempt'))
        interval = FAILURE_RETRY_HOURS
    if anchor is None:
        return -1.0
    now = datetime.now(timezone.utc)
    return interval - (now - anchor).total_seconds() / 3600.0


def run_once(engine: Optional[SubscriptionEngine] = None, force: bool = False) -> Dict[str, Any]:
    engine = engine or SubscriptionEngine()
    subs: List[Dict[str, Any]] = engine.list_subscriptions()
    state = load_state()
    now_iso = datetime.now(timezone.utc).isoformat()
    results: List[Dict[str, Any]] = []
    any_success = False
    any_failure = False

    for sub in subs:
        sub_id = str(sub.get('id') or '')
        if ONLY_IDS and sub_id not in ONLY_IDS:
            continue
        if not refreshable(sub):
            continue
        entry = state.get(sub_id) or {}
        gap = due_hours(sub, entry)
        if not force and gap >= 0:
            results.append({'id': sub_id, 'skipped': 'not-due', 'due_in_hours': round(gap, 2)})
            continue
        res = engine.update_subscription(sub_id, refresh=True)
        ok = bool(res.get('success'))
        if ok:
            entry.update({'last_attempt': now_iso, 'last_success': now_iso, 'last_error': None})
        else:
            # 不写 last_success: 保持走 1h 失败退避而非 6h 正常间隔
            entry.update({'last_attempt': now_iso, 'last_error': res.get('error')})
        state[sub_id] = entry
        any_success = any_success or ok
        any_failure = any_failure or not ok
        results.append({'id': sub_id, 'ok': ok, **({
            'error': res.get('error'),
        } if not ok else {
            'nodes': (res.get('subscription') or {}).get('node_count'),
            'injected': (res.get('inject') or {}).get('injected'),
        })})

    if results:
        save_state(state)

    published = False
    if any_success:
        # 指纹未变时 publish 是 no-op (published: False), 指纹变了才落盘新导出。
        try:
            published = bool(engine.publish_client_clash_config(fetch_remote=False).get('published'))
        except Exception as e:  # 导出失败不掩盖刷新结果, 但要可见
            results.append({'id': '_client_export', 'ok': False, 'error': str(e)[:200]})
            any_failure = True

    return {'refreshed': len([r for r in results if 'ok' in r]),
            'any_success': any_success, 'ok': not any_failure,
            'client_export_published': published, 'results': results}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--force', action='store_true', help='忽略到期/退避, 立即刷新')
    ap.add_argument('--status', action='store_true', help='只打印到期状态, 不刷新')
    args = ap.parse_args()

    if args.status:
        engine = SubscriptionEngine()
        state = load_state()
        for sub in engine.list_subscriptions():
            if not refreshable(sub):
                print(f"{sub.get('id')}: skipped (not refreshable)")
                continue
            entry = state.get(str(sub.get('id'))) or {}
            gap = due_hours(sub, entry)
            mark = 'DUE' if gap < 0 else f"due in {gap:.1f}h"
            err = f" last_error={entry.get('last_error')}" if entry.get('last_error') else ''
            print(f"{sub.get('id')}: {mark}{err}")
        return 0

    summary = run_once(force=args.force)
    print(json.dumps(summary, ensure_ascii=False))
    return 0 if summary['ok'] else 1


if __name__ == '__main__':
    sys.exit(main())
