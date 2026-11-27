"""sub-auto-refresh: 服务端订阅自动刷新的到期/退避/准入/导出触发逻辑。"""
import importlib.util
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

ROOT = Path(__file__).resolve().parent.parent

_spec = importlib.util.spec_from_file_location("sub_auto_refresh", ROOT / "clash" / "sub-auto-refresh.py")
sar = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sar)


@pytest.fixture(autouse=True)
def _state_file(tmp_path, monkeypatch):
    monkeypatch.setattr(sar, "STATE_FILE", tmp_path / "auto-refresh-state.json")
    monkeypatch.setattr(sar, "ROOT", tmp_path)


def _sub(sub_id="hutao", enabled=True, sub_type="remote", url="https://x.example/s",
         self_published=None, raw_content=None):
    s = {"id": sub_id, "enabled": enabled, "type": sub_type, "url": url}
    if self_published:
        s["self_published"] = True
    if raw_content is not None:
        s["raw_content"] = raw_content
    return s


def _entry(hours_ago=10, success=True):
    t = datetime.now(timezone.utc) - timedelta(hours=hours_ago)
    key = "last_success" if success else "last_attempt"
    return {key: t.isoformat(), "last_error": None if success else "Fetch failed: boom"}


# ------------------------------------------------------------- refreshable 准入
def test_refreshable_remote_with_url():
    assert sar.refreshable(_sub()) is True


def test_refreshable_skips_disabled():
    assert sar.refreshable(_sub(enabled=False)) is False


def test_refreshable_skips_raw():
    assert sar.refreshable(_sub(sub_type="raw", raw_content="proxies: []")) is False


def test_refreshable_skips_self_published():
    assert sar.refreshable(_sub(self_published=True)) is False


def test_refreshable_skips_missing_url():
    assert sar.refreshable(_sub(url="")) is False


# ------------------------------------------------------------- due_hours 到期
def test_due_when_never_attempted():
    assert sar.due_hours({}) == -1.0  # 负数 = 已到期


def test_due_when_interval_elapsed():
    # 距上次成功 10h > 默认 6h -> 到期
    assert sar.due_hours(_entry(hours_ago=10)) < 0


def test_not_due_within_interval():
    # 距上次成功 1h < 6h -> 未到期
    assert sar.due_hours(_entry(hours_ago=1)) > 0


def test_failure_retry_uses_short_backoff():
    # 上次失败 2h 后: 成功间隔(6h)会判未到期, 失败退避(1h)必须已到期
    assert sar.due_hours(_entry(hours_ago=2, success=False)) < 0


def test_success_then_failure_loses_old_success_anchor():
    # P1 回归: once-successful 订阅开始失败后, 退避锚在 last_attempt 上,
    # 不被残留的旧 last_success 钉死成"永远到期" (否则每 120s 锤一次上游)。
    t_attempt = datetime.now(timezone.utc) - timedelta(hours=0.2)
    entry = {"last_success": (datetime.now(timezone.utc) - timedelta(hours=7)).isoformat(),
             "last_attempt": t_attempt.isoformat(), "last_error": "Fetch failed: boom"}
    # 失败仅 0.2h 前 < 1h 退避 -> 未到期 (旧逻辑会因 7h 前的 last_success 判到期)
    assert sar.due_hours(entry) > 0


def test_failure_backoff_expires_after_retry_window():
    t_attempt = datetime.now(timezone.utc) - timedelta(hours=2)
    entry = {"last_attempt": t_attempt.isoformat(), "last_error": "boom"}
    assert sar.due_hours(entry) < 0


def test_naive_timestamp_does_not_crash():
    # P3 回归: 手改/迁移产生的 naive 时间戳不能让减法 TypeError 崩掉整轮
    assert sar.due_hours({"last_success": "2026-11-28T08:00:00"}) is not None


def test_unparseable_anchor_means_due():
    assert sar.due_hours({"last_success": "garbage"}) == -1.0


# ------------------------------------------------------------- run_once 主流程
def _engine(subs, update_results=None, published=False):
    eng = MagicMock()
    eng.list_subscriptions.return_value = subs
    if update_results is None:
        update_results = {}
    side = []
    for s in subs:
        side.append(update_results.get(s["id"], {"success": True,
                                                 "subscription": {"node_count": 35},
                                                 "inject": {"injected": 35}}))
    eng.update_subscription.side_effect = side
    eng.publish_client_clash_config.return_value = {"published": published}
    return eng


def test_run_once_refreshes_due_and_persists_state():
    eng = _engine([_sub()])
    summary = sar.run_once(engine=eng)
    assert eng.update_subscription.call_count == 1
    assert summary["any_success"] is True
    assert summary["ok"] is True
    state = json.loads(sar.STATE_FILE.read_text())
    assert state["hutao"]["last_success"] and state["hutao"]["last_error"] is None


def test_run_once_skips_not_due_without_update_call():
    eng = _engine([_sub()])
    sar.STATE_FILE.write_text(json.dumps({"hutao": _entry(hours_ago=1)}))
    summary = sar.run_once(engine=eng)
    assert eng.update_subscription.call_count == 0
    assert summary["results"][0]["skipped"] == "not-due"


def test_run_once_force_ignores_state():
    eng = _engine([_sub()])
    sar.STATE_FILE.write_text(json.dumps({"hutao": _entry(hours_ago=1)}))
    sar.run_once(engine=eng, force=True)
    assert eng.update_subscription.call_count == 1


def test_run_once_publishes_client_export_only_after_success():
    eng = _engine([_sub()], published=True)
    summary = sar.run_once(engine=eng)
    assert eng.publish_client_clash_config.call_count == 1
    assert summary["client_export_published"] is True


def test_run_once_no_publish_when_all_skipped():
    eng = _engine([_sub()])
    sar.STATE_FILE.write_text(json.dumps({"hutao": _entry(hours_ago=1)}))
    summary = sar.run_once(engine=eng)
    assert eng.publish_client_clash_config.call_count == 0
    assert summary["client_export_published"] is False


def test_run_once_failure_records_error_and_exit_code():
    eng = _engine([_sub()], update_results={
        "hutao": {"success": False, "error": "Fetch failed: boom", "subscription": {}}})
    summary = sar.run_once(engine=eng)
    assert summary["ok"] is False
    state = json.loads(sar.STATE_FILE.read_text())
    assert state["hutao"]["last_error"] == "Fetch failed: boom"
    # 失败不推进 last_success, 走 1h 退避而非 6h
    assert "last_success" not in state["hutao"]


def test_run_once_failure_still_publishes_previous_successes():
    # 同批内 share 成功 / hutao 失败: 成功的那份仍要触发导出重渲染
    subs = [_sub(sub_id="hutao"), _sub(sub_id="share")]
    eng = _engine(subs, update_results={
        "hutao": {"success": False, "error": "boom", "subscription": {}},
        "share": {"success": True, "subscription": {"node_count": 19}, "inject": {"injected": 0}},
    }, published=True)
    summary = sar.run_once(engine=eng)
    assert summary["any_success"] is True and summary["ok"] is False
    assert eng.publish_client_clash_config.call_count == 1


def test_run_once_skips_self_published_and_raw_entirely():
    subs = [_sub(sub_id="a"), _sub(sub_id="mp", self_published=True),
            _sub(sub_id="r", sub_type="raw", raw_content="x")]
    eng = _engine(subs)
    sar.run_once(engine=eng)
    ids = [c.args[0] for c in eng.update_subscription.call_args_list]
    assert ids == ["a"]


def test_run_once_ids_filter():
    eng = _engine([_sub(sub_id="hutao"), _sub(sub_id="pokemon")])
    with patch.object(sar, "ONLY_IDS", {"pokemon"}):
        sar.run_once(engine=eng)
    ids = [c.args[0] for c in eng.update_subscription.call_args_list]
    assert ids == ["pokemon"]


def test_run_once_export_failure_marks_summary_failed():
    eng = _engine([_sub()])
    eng.publish_client_clash_config.side_effect = Exception("render: bad yaml")
    summary = sar.run_once(engine=eng)
    assert summary["ok"] is False
    export_row = [r for r in summary["results"] if r.get("id") == "_client_export"]
    assert export_row and "bad yaml" in export_row[0]["error"]


def test_run_once_engine_exception_survives_and_persists_state():
    # P1-2 回归: 单订阅异常不中断整批, 已刷新订阅的 state 仍落盘
    subs = [_sub(sub_id="first"), _sub(sub_id="boom"), _sub(sub_id="third")]
    results = [
        {"success": True, "subscription": {"node_count": 5}, "inject": {"injected": 5}},
        Exception("kaboom"),  # 中途抛异常
        {"success": True, "subscription": {"node_count": 7}, "inject": {"injected": 7}},
    ]
    eng = _engine(subs, published=True)
    eng.update_subscription.side_effect = results
    summary = sar.run_once(engine=eng)
    assert eng.update_subscription.call_count == 3  # 全部订阅都被尝试
    assert summary["any_success"] is True and summary["ok"] is False
    state = json.loads(sar.STATE_FILE.read_text())
    assert state["first"]["last_success"] is not None
    assert state["third"]["last_success"] is not None
    assert state["boom"]["last_error"] == "Exception: kaboom"
    assert "last_success" not in state["boom"]


def test_run_once_prunes_deleted_sub_state():
    # 删掉订阅后, 其残留 state 条目应被清理 (ONLY_IDS 为空时)
    subs = [_sub(sub_id="alive")]
    eng = _engine(subs, published=True)
    sar.STATE_FILE.write_text(json.dumps({
        "alive": {"last_success": "2026-11-28T00:00:00Z"},
        "dead": {"last_success": "2026-11-01T00:00:00Z"},  # 已删订阅的残留
    }))
    summary = sar.run_once(engine=eng)
    state = json.loads(sar.STATE_FILE.read_text())
    assert "alive" in state
    assert "dead" not in state


def test_run_once_no_tmp_leftover():
    eng = _engine([_sub()], published=True)
    sar.run_once(engine=eng)
    # save_state 的 pid-suffixed tmp 不得在 STATE_FILE 旁残留
    leftovers = list(sar.STATE_FILE.parent.glob("auto-refresh-state.json.tmp.*"))
    assert not leftovers, f"tmp leftover: {leftovers}"


# ------------------------------------------------------------- CLI 退出码
def test_main_exit_code_failure(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["sub-auto-refresh.py"])
    eng = _engine([_sub()], update_results={
        "hutao": {"success": False, "error": "boom", "subscription": {}}})
    with patch.object(sar, "SubscriptionEngine", return_value=eng):
        assert sar.main() == 1


def test_main_exit_code_success(tmp_path, monkeypatch):
    monkeypatch.setattr("sys.argv", ["sub-auto-refresh.py"])
    eng = _engine([_sub()])
    with patch.object(sar, "SubscriptionEngine", return_value=eng):
        assert sar.main() == 0
