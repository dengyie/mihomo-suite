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
        _proxy("[自建] 🇯🇵VLESS-AWS-Tokyo-Reality", "52.192.36.79", 443),
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

    data, _, _, _ = ali.build_data(target, pool, set(), pool_proxies=pool)
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
    data, _, _, _ = ali.build_data(target, pool, {"TUIC-Azure"}, pool_proxies=pool)
    assert HK_TUIC not in _names(data)
    assert IN_INDIA_FLAGGED in _names(data)


def test_build_data_refreshes_changed_self_built_fields(tmp_path, pool):
    """A pool port/credential change must reach an existing live node (P1)."""
    tokyo = "[自建] 🇯🇵VLESS-AWS-Tokyo-Reality"
    target = tmp_path / "config.yaml"
    target.write_text(yaml.safe_dump({
        "proxies": [_proxy(tokyo, "52.192.36.79", 56667)],
        "proxy-groups": [{"name": "🌐 本机导入", "type": "select", "proxies": [tokyo]}],
        "rules": ["MATCH,PROXY"],
    }, allow_unicode=True), encoding="utf-8")

    data, added, removed, refreshed = ali.build_data(target, pool, set(), pool_proxies=pool)
    node = next(p for p in data["proxies"] if p["name"] == tokyo)
    assert node["port"] == 443
    assert refreshed == 1
    assert removed == 0
    assert sum(1 for p in data["proxies"] if p["name"] == tokyo) == 1


def test_build_data_field_refresh_is_idempotent(tmp_path, pool):
    tokyo = "[自建] 🇯🇵VLESS-AWS-Tokyo-Reality"
    target = tmp_path / "config.yaml"
    target.write_text(yaml.safe_dump({
        "proxies": [_proxy(tokyo, "52.192.36.79", 56667)],
        "proxy-groups": [{"name": "🌐 本机导入", "type": "select", "proxies": [tokyo]}],
        "rules": ["MATCH,PROXY"],
    }, allow_unicode=True), encoding="utf-8")

    data1, *_ = ali.build_data(target, pool, set(), pool_proxies=pool)
    target.write_text(yaml.safe_dump(data1, allow_unicode=True, sort_keys=False), encoding="utf-8")
    data2, added2, removed2, refreshed2 = ali.build_data(target, pool, set(), pool_proxies=pool)
    assert refreshed2 == 0
    assert added2 == 0 and removed2 == 0
    assert yaml.safe_dump(data1, allow_unicode=True, sort_keys=False) == \
        yaml.safe_dump(data2, allow_unicode=True, sort_keys=False)


def test_build_data_never_touches_live_only_legacy_nodes(tmp_path, pool):
    legacy = "[自建] 🇺🇸GVPS-AnyTLS-googlevps"
    target = tmp_path / "config.yaml"
    target.write_text(yaml.safe_dump({
        "proxies": [_proxy(legacy, "vps.mango9502.cc.cd", 60629, "anytls")],
        "proxy-groups": [{"name": "🌐 本机导入", "type": "select", "proxies": [legacy]}],
        "rules": ["MATCH,PROXY"],
    }, allow_unicode=True), encoding="utf-8")

    data, added, removed, refreshed = ali.build_data(target, pool, set(), pool_proxies=pool)
    node = next(p for p in data["proxies"] if p["name"] == legacy)
    assert node["port"] == 60629  # live-only node untouched by the pool
    assert refreshed == 0
    assert removed == 0
    assert sum(1 for p in data["proxies"] if p["name"] == legacy) == 1


def _airport_target(tmp_path, live_nodes):
    target = tmp_path / "config.yaml"
    target.write_text(yaml.safe_dump({
        "proxies": live_nodes,
        "proxy-groups": [{"name": "PROXY", "type": "select",
                          "proxies": [n["name"] for n in live_nodes]}],
        "rules": ["MATCH,PROXY"],
    }, allow_unicode=True), encoding="utf-8")
    return target


def test_build_data_refreshes_rotated_airport_import_node(tmp_path):
    """A subscription refresh rotates an airport node's server/port upstream;
    the live config must follow or the kernel keeps dialling a dead endpoint."""
    airport = "[share] 🇸🇬SG-Vmess(Example)"
    imported = [_proxy(airport, "192.0.2.20", 30002, "vmess")]
    target = _airport_target(tmp_path, [_proxy(airport, "192.0.2.10", 30001, "vmess")])

    data, added, removed, refreshed = ali.build_data(target, imported, set(), pool_proxies=imported)
    node = next(p for p in data["proxies"] if p["name"] == airport)
    assert (node["server"], node["port"]) == ("192.0.2.20", 30002)
    assert refreshed == 1 and added == 0 and removed == 0


def test_airport_refresh_keeps_host_owned_dialer_proxy(tmp_path):
    """Each host owns its airport chaining: a live dialer survives a pool copy
    with a different (or no) dialer, and a live node without one gains none."""
    chained = "[tomorin] CH Example Chained"
    plain = "[tomorin] JP Example Plain"
    imported = [
        _dialer_node(chained, "192.0.2.31", 443, "[自建] 🇺🇸Example-Dialer"),
        _dialer_node(plain, "192.0.2.41", 443, "[自建] 🇺🇸Example-Dialer"),
    ]
    target = _airport_target(tmp_path, [
        _dialer_node(chained, "192.0.2.30", 443, "mesh-relay-pool"),
        _proxy(plain, "192.0.2.40", 443),
    ])

    data, *_ , refreshed = ali.build_data(target, imported, set(), pool_proxies=imported)
    by_name = {p["name"]: p for p in data["proxies"]}
    assert by_name[chained]["server"] == "192.0.2.31"
    assert by_name[chained]["dialer-proxy"] == "mesh-relay-pool"
    assert by_name[plain]["server"] == "192.0.2.41"
    assert "dialer-proxy" not in by_name[plain]
    assert refreshed == 2


def test_airport_refresh_skips_disabled_and_dialer_only_diffs(tmp_path):
    """A disabled pool node is pruned, not refreshed, and a diff that is only the
    host-owned dialer is not a refresh (keeps the keeper reporting unchanged)."""
    dead = "[share] 🇩🇪DE-Example"
    chained = "[tomorin] CH Example Chained"
    imported = [
        _proxy(dead, "192.0.2.51", 443),
        _dialer_node(chained, "192.0.2.30", 443, "[自建] 🇺🇸Example-Dialer"),
    ]
    target = _airport_target(tmp_path, [
        _proxy(dead, "192.0.2.50", 443),
        _dialer_node(chained, "192.0.2.30", 443, "mesh-relay-pool"),
    ])

    data, *_ , refreshed = ali.build_data(target, imported, {dead}, pool_proxies=imported)
    by_name = {p["name"]: p for p in data["proxies"]}
    assert dead not in by_name  # disabled nodes are pruned, never re-imported
    assert by_name[chained]["dialer-proxy"] == "mesh-relay-pool"
    assert refreshed == 0


def test_same_upstream_port_is_text_agnostic():
    assert ali.same_upstream(
        _proxy("X", "1.2.3.4", "443"), _proxy("Y", "1.2.3.4", 443)
    )
    assert not ali.same_upstream(
        _proxy("X", "1.2.3.4", 443), _proxy("Y", "1.2.3.4", 446)
    )


def test_rules_only_rewrite_node_in_last_segment(tmp_path, pool):
    """Lock the documented contract: only the last rule segment is a node."""
    data = {
        "proxies": [_proxy(IN_INDIA, "20.198.2.112", 56667)],
        "proxy-groups": [{"name": "PROXY", "type": "select", "proxies": [IN_INDIA, "DIRECT"]}],
        "listeners": [],
        "rules": [
            "IN-USER,zen_key_2," + IN_INDIA,
            "IP-CIDR,20.198.2.112," + IN_INDIA + ",no-resolve",
        ],
    }
    nodes, refs = ali.rename_self_built(data, pool)
    assert nodes == 1
    assert refs >= 1
    assert data["rules"][0] == "IN-USER,zen_key_2," + IN_INDIA_FLAGGED
    # node followed by a modifier is not in the last segment -> left untouched
    assert data["rules"][1] == "IP-CIDR,20.198.2.112," + IN_INDIA + ",no-resolve"


def test_atomic_write_preserves_mode_and_leaves_no_temp(tmp_path):
    target = tmp_path / "config.yaml"
    target.write_text("old\n", encoding="utf-8")
    target.chmod(0o664)

    ali.atomic_write_text(target, "new\n")

    assert target.read_text(encoding="utf-8") == "new\n"
    assert (target.stat().st_mode & 0o777) == 0o664
    assert [p.name for p in tmp_path.iterdir()] == ["config.yaml"]


def test_atomic_write_keeps_original_when_replace_fails(tmp_path, monkeypatch):
    target = tmp_path / "config.yaml"
    target.write_text("original\n", encoding="utf-8")

    def boom(src, dst):
        raise OSError("nfs hiccup")

    monkeypatch.setattr(ali.os, "replace", boom)
    with pytest.raises(OSError):
        ali.atomic_write_text(target, "replacement\n")

    assert target.read_text(encoding="utf-8") == "original\n"
    assert [p.name for p in tmp_path.iterdir()] == ["config.yaml"]


def test_pool_groups_sync_google_openai_claude(tmp_path):
    target = tmp_path / "config.yaml"
    initial_config = {
        "proxies": [
            _proxy(HK_TUIC, "104.208.65.233", 47931, "tuic"),
            _proxy("[自建] 🇺🇸VLESS-AWS-Oregon-Reality", "32.189.158.231", 443),
            _proxy("美国_BGP_A", "1.2.3.4", 443),
        ],
        "proxy-groups": [
            {"name": "PROXY", "type": "select", "proxies": ["美国_BGP_A", "DIRECT"]},
            {"name": "🎯Google", "type": "select", "proxies": ["美国_BGP_A"]},
            {"name": "🎯OpenAI", "type": "select", "proxies": ["美国_BGP_A"]},
        ],
    }
    target.write_text(yaml.safe_dump(initial_config))

    pool_groups = {
        "google": ["美国_BGP_A", "[自建] 🇺🇸VLESS-AWS-Oregon-Reality"],
        "openai": ["美国_BGP_A", "[自建] 🇺🇸VLESS-AWS-Oregon-Reality"],
        "claude": ["美国_BGP_A", "[自建] 🇺🇸VLESS-AWS-Oregon-Reality"],
    }

    pool_proxies = initial_config["proxies"]
    data, _, _, _ = ali.build_data(
        target, pool_proxies, set(), pool_proxies=pool_proxies, pool_groups=pool_groups
    )

    group_map = {g["name"]: g for g in data["proxy-groups"]}
    assert "[自建] 🇺🇸VLESS-AWS-Oregon-Reality" in group_map["🎯Google"]["proxies"]
    assert "[自建] 🇺🇸VLESS-AWS-Oregon-Reality" in group_map["🎯OpenAI"]["proxies"]
    assert "🎯Claude" in group_map
    assert "[自建] 🇺🇸VLESS-AWS-Oregon-Reality" in group_map["🎯Claude"]["proxies"]
    assert group_map["🎯Claude"]["type"] == "select"


def test_build_data_deduplicates_proxy_groups(tmp_path):
    target = tmp_path / "config.yaml"
    us_oregon = "[自建] 🇺🇸VLESS-AWS-Oregon-Reality"
    initial_config = {
        "proxies": [
            _proxy(HK_TUIC, "104.208.65.233", 47931, "tuic"),
            _proxy("[自建] 🇺🇸TUIC-googlevps", "1.2.3.4", 443),
            _proxy(us_oregon, "32.189.158.231", 443),
        ],
        "proxy-groups": [
            {"name": "PROXY", "type": "select", "proxies": ["[自建] 🇺🇸TUIC-googlevps", HK_TUIC, "[自建] 🇺🇸TUIC-googlevps", "DIRECT"]},
            {"name": "AUTO", "type": "url-test", "proxies": [us_oregon, us_oregon]},
        ],
        "rules": ["MATCH,PROXY"],
    }
    target.write_text(yaml.safe_dump(initial_config))

    data, _, _, _ = ali.build_data(target, [], set(), pool_proxies=[])
    group_map = {g["name"]: g for g in data["proxy-groups"]}
    assert group_map["PROXY"]["proxies"] == ["[自建] 🇺🇸TUIC-googlevps", HK_TUIC, "DIRECT"]
    assert group_map["AUTO"]["proxies"] == [us_oregon]


def test_build_data_cpa_clean_egress_puts_home_win_mesh_first(tmp_path):
    target = tmp_path / "config.yaml"
    initial_config = {
        "proxies": [
            _proxy(IN_MESH, "10.144.144.10", 8082),
            _proxy("[自建] 🏠home-win-CF", "1.2.3.4", 443),
        ],
        "proxy-groups": [
            {"name": "cpa-clean-egress", "type": "select", "proxies": ["[自建] 🏠home-win-CF", "PROXY", "DIRECT"]},
        ],
        "rules": ["MATCH,cpa-clean-egress"],
    }
    target.write_text(yaml.safe_dump(initial_config))

    data, _, _, _ = ali.build_data(target, [], set(), pool_proxies=[])
    cpa = next(g for g in data["proxy-groups"] if g["name"] == "cpa-clean-egress")
    assert cpa["proxies"][0] == IN_MESH
    assert cpa["proxies"][1] == "[自建] 🏠home-win-CF"




# --- gateway-only relays (airports/gateway-relays.yaml) ---------------------
TOKYO = "[自建] 🇯🇵VLESS-AWS-Tokyo-Reality"
V6 = "[tomorin] HK LUCID TCP IPv6"
SELF_V6 = "[自建] 🇺🇸Mesh-googlevps-EasyTier"


def _relay_target(tmp_path):
    target = tmp_path / "config.yaml"
    target.write_text(yaml.safe_dump({
        "proxies": [_proxy(TOKYO, "52.192.36.79", 443),
                    _proxy(SELF_V6, "2600::1", 443)],
        "proxy-groups": [{"name": "PROXY", "type": "select", "proxies": ["DIRECT"]}],
        "rules": ["MATCH,PROXY"],
    }, allow_unicode=True), encoding="utf-8")
    return target


def _relay_pool():
    # V6 lives in the pool file but NOT in vps-import (IPv6-only, ipv6-skip)
    return [_proxy(TOKYO, "52.192.36.79", 443),
            _proxy(SELF_V6, "2600::1", 443),
            _proxy(V6, "2001:db8::1", 443)]


def test_gateway_relay_adds_pool_node_with_dialer_and_survives_sweep(tmp_path):
    target = _relay_target(tmp_path)
    imported = [_proxy(TOKYO, "52.192.36.79", 443), _proxy(SELF_V6, "2600::1", 443)]
    relays = {V6: TOKYO, SELF_V6: TOKYO}
    data, *_ = ali.build_data(target, imported, set(), _relay_pool(), gateway_relays=relays)
    by = {p["name"]: p for p in data["proxies"]}
    assert by[V6]["dialer-proxy"] == TOKYO
    assert by[V6]["server"] == "2001:db8::1"
    # self-built refresh must not wipe the gateway-only dialer
    assert by[SELF_V6]["dialer-proxy"] == TOKYO
    # never added to any group: production routing untouched
    for g in data["proxy-groups"]:
        assert V6 not in g["proxies"]


def test_gateway_relay_is_idempotent(tmp_path):
    target = _relay_target(tmp_path)
    relays = {V6: TOKYO}
    data, *_ = ali.build_data(target, [], set(), _relay_pool(), gateway_relays=relays)
    target.write_text(yaml.safe_dump(data, allow_unicode=True, sort_keys=False, width=120))
    again, *_ = ali.build_data(target, [], set(), _relay_pool(), gateway_relays=relays)
    assert yaml.safe_dump(again, allow_unicode=True, sort_keys=False, width=120) == target.read_text()


def test_gateway_relay_skips_missing_dialer_disabled_and_unknown(tmp_path):
    target = tmp_path / "config.yaml"
    target.write_text(yaml.safe_dump({
        "proxies": [_proxy("x", "1.1.1.1", 1)],
        "proxy-groups": [{"name": "PROXY", "type": "select", "proxies": ["DIRECT"]}],
    }, allow_unicode=True), encoding="utf-8")
    relays = {V6: TOKYO, "[tomorin] nope": TOKYO}
    data, *_ = ali.build_data(target, [], set(), _relay_pool(), gateway_relays=relays)
    assert V6 not in _names(data)  # dialer absent from this config -> skip
    data, *_ = ali.build_data(_relay_target(tmp_path), [], {V6}, _relay_pool(),
                              gateway_relays={V6: TOKYO})
    assert V6 not in _names(data)  # disabled wins


def test_load_gateway_relays(tmp_path, monkeypatch):
    monkeypatch.setattr(ali, "ROOT", tmp_path)
    assert ali.load_gateway_relays() == {}
    (tmp_path / "airports").mkdir()
    (tmp_path / "airports" / "gateway-relays.yaml").write_text(yaml.safe_dump(
        {"default-dialer": TOKYO, "relays": [V6, {"name": SELF_V6, "dialer": "other"}, "", 3]},
        allow_unicode=True), encoding="utf-8")
    assert ali.load_gateway_relays() == {V6: TOKYO, SELF_V6: "other"}


def test_gateway_relay_new_node_never_joins_pool_groups(tmp_path):
    target = tmp_path / "config.yaml"
    target.write_text(yaml.safe_dump({
        "proxies": [_proxy(TOKYO, "52.192.36.79", 443)],
        "proxy-groups": [{"name": "🎯Google", "type": "select", "proxies": [TOKYO]}],
    }, allow_unicode=True), encoding="utf-8")
    data, *_ = ali.build_data(target, [], set(), _relay_pool(),
                              pool_groups={"google": [SELF_V6, TOKYO]},
                              gateway_relays={SELF_V6: TOKYO})
    assert SELF_V6 in _names(data)
    google = next(g for g in data["proxy-groups"] if g["name"] == "🎯Google")
    assert google["proxies"] == [TOKYO]


def test_gateway_relay_stays_out_of_groups_on_later_runs(tmp_path):
    target = tmp_path / "config.yaml"
    target.write_text(yaml.safe_dump({
        "proxies": [_proxy(TOKYO, "52.192.36.79", 443)],
        "proxy-groups": [{"name": "🎯Google", "type": "select", "proxies": [TOKYO]}],
    }, allow_unicode=True), encoding="utf-8")
    kw = dict(pool_groups={"google": [SELF_V6, TOKYO]}, gateway_relays={SELF_V6: TOKYO})
    for _ in range(2):  # second run: the relayed node is already present
        data, *_ = ali.build_data(target, [], set(), _relay_pool(), **kw)
        target.write_text(yaml.safe_dump(data, allow_unicode=True, sort_keys=False, width=120))
    google = next(g for g in data["proxy-groups"] if g["name"] == "🎯Google")
    assert google["proxies"] == [TOKYO]
