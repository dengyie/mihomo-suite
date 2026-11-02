"""Regression tests for clash/probe_clash_nodes.py name matching.

The register-batch probe selects its preferred node by comparing
``bare_name()`` of live names against ``PREFERRED``. After the 2026-11-03
``[自建] `` + region-flag rename those two must still line up, and airport
names must never have their own leading flag stripped.
"""

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

_spec = importlib.util.spec_from_file_location(
    "probe_clash_nodes", ROOT / "clash" / "probe_clash_nodes.py"
)
pcn = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pcn)


def test_bare_name_strips_only_self_built_tag_and_flag():
    assert pcn.bare_name("[自建] 🇺🇸TUIC-googlevps") == "TUIC-googlevps"
    assert pcn.bare_name("[自建] TUIC-googlevps") == "TUIC-googlevps"
    assert pcn.bare_name("TUIC-googlevps") == "TUIC-googlevps"
    # airport names keep their own flag
    assert pcn.bare_name("🇸🇬【亚洲】新加坡03丨直连") == "🇸🇬【亚洲】新加坡03丨直连"


def test_preferred_matches_live_canonical_names():
    live = [
        "[自建] 🇺🇸TUIC-googlevps",
        "[自建] 🇺🇸AnyTLS-googlevps",
        "VLESS-CF-DLD",
        "[自建] 🇭🇰TUIC-Azure",
    ]
    preferred_first = [n for n in live if pcn.bare_name(n) in pcn.PREFERRED]
    assert preferred_first == [
        "[自建] 🇺🇸TUIC-googlevps",
        "[自建] 🇺🇸AnyTLS-googlevps",
        "VLESS-CF-DLD",
    ]


def test_preferred_has_no_retired_legacy_names():
    # the GVPS-* twins were retired; the list must track current pool names
    for stale in ("GVPS-TUIC-googlevps", "GVPS-AnyTLS-googlevps", "GVPS-VLESS-CF-LSJ"):
        assert stale not in pcn.PREFERRED
