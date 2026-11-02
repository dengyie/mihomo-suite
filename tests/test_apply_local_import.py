"""Regression tests for clash/apply-local-import.py.

Covers the ``[自建] `` tag + region-flag naming contract and the same-upstream
twin retirement that keeps the live configs converged on the pool file:

* bare -> tagged rename, stale tagged -> pool canonical (by upstream)
* duplicate twins retired only when they dial the same server/port/type
* the home-win-mesh self-map guard (never retires itself)
* structural reference rewriting (groups / listeners / rules / dialer-proxy)
* flag stripping only applies to self-built names
* idempotency: a second pass is a no-op
"""

import importlib.util
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent

_spec = importlib.util.spec_from_file_location(
    "apply_local_import", ROOT / "clash" / "apply-local-import.py"
)
ali = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ali)

SELF_TAG = ali.SELF_TAG
HK_TUIC = "[自建] 🇭🇰TUIC-Azure"
IN_TUIC = "[自建] TUIC-Azure"
IN_INDIA = "[自建] VLESS-India-Reality"
IN_INDIA_FLAGGED = "[自建] 🇮🇳VLESS-India-Reality"
IN_MESH = "[自建] 🏠home-win-mesh"
AIRPORT = "🇸🇬【亚洲】新加坡03丨直连"


def _proxy(name, server, port, ptype="vless", **extra):
    return {"name": name, "server": server, "port": port, "type": ptype, **extra}


def _dialer_node(name, server, port, dialer):
    """A proxy whose ``dialer-proxy`` (hyphenated key, as Clash writes it) is set."""
    node = _proxy(name, server, port)
    node["dialer-proxy"] = dialer
    return node


@pytest.fixture
def pool():
    """The pool file (source of truth) as the keeper sees it."""
    return [
        _proxy(HK_TUIC, "104.208.65.233", 47931, "tuic"),
        _proxy(IN_INDIA_FLAGGED, "20.198.2.112", 56667),
        _proxy("[自建] 🇯🇵VLESS-AWS-Tokyo-Reality", "52.192.36.79", 56667),
        _proxy(IN_MESH, "127.0.0.1", 10882, "socks5"),
    ]


@pytest.fixture
def live():
    """A live config still carrying pre-flag / duplicate spellings."""
    return {
        "proxies": [
            _proxy(IN_TUIC, "104.208.65.233", 47931, "tuic"),          # stale tagged
            _proxy("TUIC-Azure", "104.208.65.233", 47931, "tuic"),     # bare duplicate
            _proxy(IN_INDIA, "20.198.2.112", 56667),                   # pre-flag tagged
            _proxy(IN_MESH, "127.0.0.1", 10882, "socks5"),             # self-map guard
            _proxy(AIRPORT, "1.2.3.4", 443),                           # airport, untouched
            dict(_proxy("[自建] 🇺🇸Muse-VM-Reality", "5.6.7.8", 443),
                 **{"dialer-proxy": "TUIC-Azure"}),
        ],
        "proxy-groups": [
            {"name": "PROXY", "type": "select",
             "proxies": ["TUIC-Azure", IN_TUIC, IN_INDIA, AIRPORT, "DIRECT"]},
        ],
        "listeners": [{"name": "egress", "port": 10818, "proxy": IN_INDIA}],
        "rules": ["IN-USER,zen_key_2," + IN_INDIA, "MATCH,PROXY"],
    }


def _names(data):
    return [p["name"] for p in data["proxies"]]


def test_strip_self_tag_only_strips_self_built_flags():
    assert ali.strip_self_tag(HK_TUIC) == "TUIC-Azure"
    assert ali.strip_self_tag(IN_TUIC) == "TUIC-Azure"
    assert ali.strip_self_tag("TUIC-Azure") == "TUIC-Azure"
    # airport names keep their own leading flag
    assert ali.strip_self_tag(AIRPORT) == AIRPORT
    assert ali.strip_self_tag("[share] 🇭🇰HK-Warp1(Sak)") == "[share] 🇭🇰HK-Warp1(Sak)"


def test_is_disabled_matches_every_historical_spelling():
    # a denylist entry under any of the three live-relevant spellings disables
    # the node no matter which spelling the config currently carries
    entry, node = "TUIC-Azure", HK_TUIC                      # bare -> flagged tagged
    assert ali.is_disabled(node, {entry})
    assert ali.is_disabled(IN_TUIC, {entry})                # bare -> pre-flag tagged
    assert ali.is_disabled(IN_TUIC, {HK_TUIC}) is False     # flagged entry vs pre-flag tagged
    assert ali.is_disabled(HK_TUIC, {IN_TUIC})              # pre-flag tagged entry vs flagged
    assert not ali.is_disabled(HK_TUIC, {"AnyTLS-Azure"})
    # airport names are matched exactly, never flag-stripped
    assert not ali.is_disabled(AIRPORT, {"【亚洲】新加坡03丨直连"})


def test_rename_converges_on_pool_canonical(live, pool):
    nodes, refs = ali.rename_self_built(live, pool)
    names = _names(live)

    assert HK_TUIC in names
    assert IN_INDIA_FLAGGED in names
    assert "TUIC-Azure" not in names
    assert IN_TUIC not in names
    assert IN_INDIA not in names
    # one canonical TUIC-Azure survives (the bare duplicate was retired)
    assert names.count(HK_TUIC) == 1
    assert nodes == 3  # stale tagged + bare dup + pre-flag tagged
    assert refs >= 1


def test_self_map_guard_keeps_home_win_mesh(live, pool):
    ali.rename_self_built(live, pool)
    assert IN_MESH in _names(live)


def test_airport_nodes_are_never_touched(live, pool):
    ali.rename_self_built(live, pool)
    assert AIRPORT in _names(live)


def test_references_follow_the_rename(live, pool):
    ali.rename_self_built(live, pool)

    members = live["proxy-groups"][0]["proxies"]
    assert HK_TUIC in members
    assert IN_INDIA_FLAGGED in members
    assert "TUIC-Azure" not in members
    assert IN_INDIA not in members
    assert AIRPORT in members and "DIRECT" in members

    assert live["listeners"][0]["proxy"] == IN_INDIA_FLAGGED
    assert live["rules"][0] == "IN-USER,zen_key_2," + IN_INDIA_FLAGGED
    assert live["rules"][1] == "MATCH,PROXY"

    muse = next(p for p in live["proxies"] if p["name"] == "[自建] 🇺🇸Muse-VM-Reality")
    assert muse["dialer-proxy"] == HK_TUIC


def test_rename_is_idempotent(live, pool):
    ali.rename_self_built(live, pool)
    snapshot = yaml.safe_dump(live, allow_unicode=True, sort_keys=False)
    nodes, refs = ali.rename_self_built(live, pool)
    assert (nodes, refs) == (0, 0)
    assert yaml.safe_dump(live, allow_unicode=True, sort_keys=False) == snapshot


def test_twin_retired_only_on_same_upstream(pool):
    """A same-named node on a different endpoint is not a twin."""
    data = {
        "proxies": [
            _proxy(HK_TUIC, "104.208.65.233", 47931, "tuic"),
            _proxy("TUIC-Azure", "104.208.65.233", 47932, "tuic"),  # other port
        ],
        "proxy-groups": [],
        "listeners": [],
        "rules": [],
    }
    ali.rename_self_built(data, pool)
    # the different-upstream node keeps its own identity (not retired)
    assert _proxy("TUIC-Azure", "104.208.65.233", 47932, "tuic") in data["proxies"]


def test_home_pref_is_flag_agnostic():
    valid = {"[自建] 🏠home-win-CF", "🏠home-win-CF", "PROXY"}
    assert ali.home_pref("🏠home-win-CF", valid) == "[自建] 🏠home-win-CF"
    assert ali.home_pref("🏠home-win-CF", {"🏠home-win-CF"}) == "🏠home-win-CF"
    assert ali.home_pref("🏠home-win-mesh", valid) is None


def test_build_data_exempts_self_built_from_orphan_pruning(tmp_path, pool):
    target = tmp_path / "config.yaml"
    target.write_text(yaml.safe_dump({
        "proxies": [
            _proxy("[机场] Stale-Node", "9.9.9.9", 443),   # orphan -> dropped
            _proxy("[自建] 🇺🇸Muse-VM-Reality", "5.6.7.8", 443),  # exempt -> kept
        ],
        "proxy-groups": [{"name": "PROXY", "type": "select", "proxies": ["DIRECT"]}],
        "rules": ["MATCH,PROXY"],
    }, allow_unicode=True), encoding="utf-8")

    data, _, _ = ali.build_data(target, pool, set(), pool_proxies=pool)
    names = _names(data)
    assert "[机场] Stale-Node" not in names
    assert "[自建] 🇺🇸Muse-VM-Reality" in names
    assert HK_TUIC in names  # pool nodes imported


def test_build_data_drops_denylisted_pool_node(tmp_path, pool):
    target = tmp_path / "config.yaml"
    target.write_text(yaml.safe_dump({
        "proxies": [],
        "proxy-groups": [{"name": "PROXY", "type": "select", "proxies": ["DIRECT"]}],
        "rules": ["MATCH,PROXY"],
    }, allow_unicode=True), encoding="utf-8")

    # denylisted under the bare name -> the flagged pool node must not be added
    data, _, _ = ali.build_data(target, pool, {"TUIC-Azure"}, pool_proxies=pool)
    assert HK_TUIC not in _names(data)
    assert IN_INDIA_FLAGGED in _names(data)
