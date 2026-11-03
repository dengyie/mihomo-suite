"""Regression tests for clash/hutao-bridge-guard.py's config write path.

The guard is a fourth writer of the live configs (it rewrites
``listeners[].proxy`` in both ``config.yaml`` and ``config.mac-merged.yaml`` on
every keeper cycle when the bridge is unhealthy). It must therefore take the
shared ``ClashConfigLock`` and replace files atomically, like the other writers.
"""

import importlib.util
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
CLASH_DIR = ROOT / "clash"


def _load():
    # The script imports ``clash_lock`` by bare name; make its dir importable.
    sys.path.insert(0, str(CLASH_DIR))
    spec = importlib.util.spec_from_file_location(
        "hutao_bridge_guard", CLASH_DIR / "hutao-bridge-guard.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


hg = _load()


def _config(proxies=3, rules=5, mixed_port=True):
    data = {
        "proxies": [
            {"name": f"p{i}", "type": "ss", "server": "1.2.3.4", "port": 1000 + i,
             "cipher": "aes-128-gcm", "password": "x"}
            for i in range(proxies)
        ],
        "proxy-groups": [],
        "rules": [f"DOMAIN,s{i}.example,DIRECT" for i in range(rules)],
        "listeners": [
            {"name": "other", "type": "mixed", "port": 1080,
             "listen": "127.0.0.1", "proxy": "p0"},
        ],
    }
    if mixed_port:
        data["mixed-port"] = 7890
    return yaml.safe_dump(data, sort_keys=False)


@pytest.fixture()
def guard_paths(tmp_path, monkeypatch):
    monkeypatch.setenv("CLASH_ROOT", str(tmp_path))
    monkeypatch.setattr(hg, "MIN_PROXIES", 1)
    monkeypatch.setattr(hg, "MIN_RULES", 1)
    cfg = tmp_path / "config.yaml"
    merged = tmp_path / "config.mac-merged.yaml"
    cfg.write_text(_config(), encoding="utf-8")
    merged.write_text(_config(), encoding="utf-8")
    cfg.chmod(0o664)
    merged.chmod(0o664)
    monkeypatch.setattr(hg, "CFG", cfg)
    monkeypatch.setattr(hg, "MERGED", merged)
    monkeypatch.setattr(hg, "LOG", tmp_path / "hutao-bridge-guard.log")
    return cfg, merged, tmp_path


def _targets(path):
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return {listener["name"]: listener.get("proxy") for listener in data["listeners"]}


def test_write_listener_updates_both_files_atomically(guard_paths):
    cfg, merged, tmp_path = guard_paths

    hg.write_listener("hutao-us-fallback")

    for path in (cfg, merged):
        assert _targets(path)[hg.LISTENER_NAME] == "hutao-us-fallback"
        assert _targets(path)["other"] == "p0"  # unrelated listener untouched
        assert (path.stat().st_mode & 0o777) == 0o664
        assert len(list(tmp_path.glob(f"{path.name}.pre-guard-*"))) == 1
    # os.replace leaves no temp file behind
    assert not list(tmp_path.glob(".*.tmp-*"))


def test_write_listener_is_reentrant_with_an_outer_lock(guard_paths):
    """Nested acquisition must not self-deadlock (keeper/gateway call style)."""
    cfg, _, _ = guard_paths

    with hg.ClashConfigLock():
        hg.write_listener("hutao-us-fallback")

    assert _targets(cfg)[hg.LISTENER_NAME] == "hutao-us-fallback"


def test_write_listener_aborts_without_writing_when_mixed_port_missing(tmp_path, monkeypatch):
    monkeypatch.setenv("CLASH_ROOT", str(tmp_path))
    monkeypatch.setattr(hg, "MIN_PROXIES", 1)
    monkeypatch.setattr(hg, "MIN_RULES", 1)
    cfg = tmp_path / "config.yaml"
    original = _config(mixed_port=False)
    cfg.write_text(original, encoding="utf-8")
    monkeypatch.setattr(hg, "CFG", cfg)
    monkeypatch.setattr(hg, "MERGED", tmp_path / "config.mac-merged.yaml")
    monkeypatch.setattr(hg, "LOG", tmp_path / "hutao-bridge-guard.log")

    with pytest.raises(SystemExit):
        hg.write_listener("hutao-us-fallback")

    assert cfg.read_text(encoding="utf-8") == original
    assert not list(tmp_path.glob("config.yaml.pre-guard-*"))
    assert not list(tmp_path.glob(".*.tmp-*"))
