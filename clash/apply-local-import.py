#!/usr/bin/env python3
"""Persist verified local nodes and an explicit denylist into live Clash configs.

The node file holds proxies plus simple name lists under ``groups``. This
script only fills ``🌐 本机导入`` from ``groups.vps-import``. url-test / PROXY /
Grok / Google strategy stays elsewhere. Unchanged files are not rewritten;
a changed live config is reloaded once through 9090.

Self-built nodes carry a ``[自建] `` name prefix and the pool file is the single
source of truth for it. This script mirrors that prefix onto every live config
(proxy names, dialer-proxy, group members, listener targets and rule
destinations) and retires the untagged twin, so a rename never leaves a
duplicate behind. Nodes whose name already carries the prefix are exempt from
the subscription-orphan sweep below.
"""
from __future__ import annotations

import os
import re
import shutil
import sys
import urllib.request
from datetime import datetime
from pathlib import Path

import yaml

ROOT = Path(os.environ.get('CLASH_ROOT', '/personal/clash')).resolve()
GROUP = '🌐 本机导入'
VPS_GROUP = 'vps-import'
SELF_TAG = '[自建] '
THIRD_PARTY_PREFIXES = tuple(
    p.strip() for p in os.environ.get('THIRD_PARTY_PREFIXES', 'SUB-,JX-,GL-,JS-,KQ-').split(',') if p.strip()
)
BLOCKED_NAMES = {'续费备用节点', 'PXED-BRIDGE'}
# Self-built nodes that only exist in the live configs (legacy 3x-ui leftovers,
# no longer produced by any active subscription). Tag them in place so they
# stop looking like airport nodes; they are never added or removed here.
# Map: bare name -> the exact tagged name the live config should carry.
LEGACY_SELF_BUILT = {
    'GVPS-AnyTLS-googlevps': '[自建] 🇺🇸GVPS-AnyTLS-googlevps',
    'GVPS-TUIC-googlevps': '[自建] 🇺🇸GVPS-TUIC-googlevps',
    'GVPS-Aliyun-BJ-SOCKS': '[自建] 🇨🇳GVPS-Aliyun-BJ-SOCKS',
    'Azure-HK-TUIC': '[自建] 🇭🇰Azure-HK-TUIC',
    '🏠home-win-mesh': '[自建] 🏠home-win-mesh',
}


def is_third_party_or_blocked(name: str) -> bool:
    if not name:
        return False
    if name in BLOCKED_NAMES:
        return True
    return any(name.startswith(pfx) for pfx in THIRD_PARTY_PREFIXES)


def is_auto_excluded(name: str) -> bool:
    if not name:
        return True
    low = name.lower()
    if low.startswith('bk-'):
        return True
    return any(k in low for k in ('azure', 'reverse', '17897', 'home-win', 'pxed-bridge'))


# A leading region flag is part of the display name ("[自建] 🇭🇰TUIC-Azure").
# Strip it for matching so denylists / whitelists / policy written against the
# bare name keep working after a flag was added.
FLAG_RE = re.compile('^[\U0001F1E6-\U0001F1FF]{2}')


def strip_self_tag(name: str) -> str:
    """Return the bare node name without the ``[自建] `` prefix or region flag."""
    if name.startswith(SELF_TAG):
        name = name[len(SELF_TAG):]
    return FLAG_RE.sub('', name)


def is_disabled(name: str, disabled: set[str]) -> bool:
    """True when the node is denylisted under either its bare or tagged name."""
    return name in disabled or strip_self_tag(name) in disabled


def same_upstream(a: dict, b: dict) -> bool:
    """True when two proxies dial the same endpoint (server/port/type)."""
    return (
        str(a.get('server')) == str(b.get('server'))
        and a.get('port') == b.get('port')
        and a.get('type') == b.get('type')
    )


def self_tag_map(proxies) -> dict[str, str]:
    """Map every already-tagged pool proxy to ``bare_name -> '[自建] name'``."""
    mapping: dict[str, str] = {}
    for proxy in proxies or []:
        if not isinstance(proxy, dict):
            continue
        name = proxy.get('name')
        if isinstance(name, str) and name.startswith(SELF_TAG) and len(name) > len(SELF_TAG):
            mapping[strip_self_tag(name)] = name
    for bare, tagged in LEGACY_SELF_BUILT.items():
        mapping.setdefault(bare, tagged)
        # configs migrated by an earlier run may already carry the old, unflagged
        # ``[自建] bare`` form; route it to the canonical (flagged) name too.
        mapping.setdefault(SELF_TAG + bare, tagged)
    return mapping


def _rename_targets(groups, listeners, rules, mapping: dict[str, str]) -> int:
    """Rewrite group members, listener ``proxy`` and rule destinations.

    Only exact matches of a bare name are rewritten; already-tagged or
    unrelated names pass through untouched. Returns number of edits.
    """
    edits = 0
    for group in groups or []:
        if not isinstance(group, dict):
            continue
        members = group.get('proxies')
        if isinstance(members, list):
            written = []
            for member in members:
                written.append(mapping.get(member, member) if isinstance(member, str) else member)
            if written != members:
                edits += 1
                group['proxies'] = written
        dialer = group.get('dialer-proxy')
        if isinstance(dialer, str) and dialer in mapping:
            group['dialer-proxy'] = mapping[dialer]
            edits += 1
    for listener in listeners or []:
        if not isinstance(listener, dict):
            continue
        target = listener.get('proxy')
        if isinstance(target, str) and target in mapping:
            listener['proxy'] = mapping[target]
            edits += 1
    if isinstance(rules, list):
        written = []
        changed = False
        for rule in rules:
            if not isinstance(rule, str):
                written.append(rule)
                continue
            head, sep, tail = rule.rpartition(',')
            if sep and tail in mapping:
                written.append(f'{head},{mapping[tail]}')
                changed = True
            else:
                written.append(rule)
        if changed:
            rules[:] = written
            edits += 1
    return edits


def upstream_key(proxy: dict) -> tuple:
    """Identity of the endpoint a proxy dials (server/port/type)."""
    return (str(proxy.get('server')), proxy.get('port'), proxy.get('type'))


def rename_self_built(data: dict, imported: list[dict]) -> tuple[int, int]:
    """Mirror the pool's ``[自建]`` names onto a live config, idempotently.

    * proxies: bare ``VLESS-Azure-Reality`` -> the pool's tagged name; when a
      twin already exists and dials the same upstream, the duplicate is retired
      instead of renamed (no duplicate names).
    * a stale tagged name (e.g. ``[自建] TUIC-Azure`` after the pool renamed the
      node to ``[自建] 🇭🇰TUIC-Azure``) adopts the pool's canonical name for its
      upstream, so a rename in the pool never leaves an old copy behind.
    * every structural reference follows: dialer-proxy, group members,
      listener ``proxy``, rule destinations.
    Returns ``(nodes_renamed_or_retired, reference_edits)``.
    """
    mapping = self_tag_map(imported)
    if not mapping:
        return 0, 0
    canonical: dict[tuple, str] = {}
    for proxy in imported or []:
        if (isinstance(proxy, dict) and isinstance(proxy.get('name'), str)
                and proxy['name'].startswith(SELF_TAG)):
            canonical.setdefault(upstream_key(proxy), proxy['name'])
    proxies = data.get('proxies') or []
    tagged = {
        p['name']: p
        for p in proxies
        if isinstance(p, dict)
        and isinstance(p.get('name'), str)
        and p['name'].startswith(SELF_TAG)
    }
    nodes = 0
    rename_map: dict[str, str] = {}
    adopted: dict[str, dict] = {}
    kept = []
    for proxy in proxies:
        if not isinstance(proxy, dict) or not isinstance(proxy.get('name'), str):
            kept.append(proxy)
            continue
        name = proxy['name']
        new_name = mapping.get(name)
        if new_name is not None and new_name == name:
            # already-canonical legacy form (e.g. 🏠home-win-mesh tag maps to
            # itself): nothing to do, and never treat it as its own twin.
            new_name = None
        if new_name is None and name.startswith(SELF_TAG) and len(name) > len(SELF_TAG):
            candidate = canonical.get(upstream_key(proxy))
            if candidate is not None and candidate != name:
                new_name = candidate
        if new_name is not None:
            twin = adopted.get(new_name) or tagged.get(new_name)
            if twin is None:
                proxy['name'] = new_name
                rename_map[name] = new_name
                adopted[new_name] = proxy
                nodes += 1
            elif same_upstream(proxy, twin):
                rename_map[name] = new_name
                nodes += 1
                continue  # duplicate of an already-canonical node; retire it
            # else: same name but a different upstream -> leave it alone.
        kept.append(proxy)
    data['proxies'] = kept
    combined = dict(mapping)
    combined.update(rename_map)
    for proxy in kept:
        if isinstance(proxy, dict):
            dialer = proxy.get('dialer-proxy')
            if isinstance(dialer, str) and dialer in combined:
                proxy['dialer-proxy'] = combined[dialer]
    refs = _rename_targets(
        data.get('proxy-groups'), data.get('listeners'), data.get('rules'), combined
    )
    return nodes, refs


def resolve_airport(root: Path) -> Path:
    env = os.environ.get('APPLY_LOCAL_IMPORT_FILE', '').strip()
    if env:
        return Path(env).resolve()
    return (root / 'airports/local-nodes.yaml').resolve()


def load_disabled() -> set[str]:
    disabled = ROOT / 'airports/disabled-nodes.txt'
    if not disabled.exists():
        return set()
    return {
        line.strip()
        for line in disabled.read_text().splitlines()
        if line.strip() and not line.lstrip().startswith('#')
    }


def normalize_simple_groups(raw) -> dict[str, list[str]]:
    groups: dict[str, list[str]] = {}
    if not isinstance(raw, dict):
        return groups
    for key, val in raw.items():
        label = str(key or '').strip()
        if not label:
            continue
        items = val.get('proxies') if isinstance(val, dict) else val
        if not isinstance(items, list):
            continue
        names: list[str] = []
        seen: set[str] = set()
        for item in items:
            if isinstance(item, str):
                name = item.strip()
            elif isinstance(item, dict):
                name = str(item.get('name') or '').strip()
            else:
                continue
            if not name or name in seen:
                continue
            seen.add(name)
            names.append(name)
        groups[label] = names
    return groups


def load_vps_import(path: Path) -> tuple[list[dict], list[str], list[dict]] | None:
    data = yaml.safe_load(path.read_text()) or {}
    if isinstance(data, list):
        proxies = data
        groups: dict[str, list[str]] = {}
    elif isinstance(data, dict):
        proxies = data.get('proxies') or []
        groups = normalize_simple_groups(data.get('groups'))
    else:
        return None
    if VPS_GROUP not in groups:
        return None
    by_name = {
        proxy.get('name'): proxy
        for proxy in proxies
        if isinstance(proxy, dict) and proxy.get('name')
    }
    names = [name for name in groups[VPS_GROUP] if name in by_name]
    imported = [by_name[name] for name in names]
    return imported, names, proxies


def home_pref(bare: str, valid_references: set[str]) -> str | None:
    """Prefer the ``[自建]``-tagged name, fall back to the bare name."""
    tagged = SELF_TAG + bare
    if tagged in valid_references:
        return tagged
    if bare in valid_references:
        return bare
    return None


def build_data(
    target: Path,
    imported: list[dict],
    disabled: set[str],
    pool_proxies: list[dict] | None = None,
) -> tuple[dict, int, int]:
    data = yaml.safe_load(target.read_text()) or {}
    rename_self_built(data, pool_proxies if pool_proxies is not None else imported)
    proxies = data.get('proxies') or []
    existing = {
        proxy.get('name')
        for proxy in proxies
        if isinstance(proxy, dict)
    }
    added = [
        proxy for proxy in imported
        if proxy.get('name') not in existing and not is_disabled(proxy.get('name'), disabled)
    ]
    if added:
        data.setdefault('proxies', []).extend(added)

    groups = data.setdefault('proxy-groups', [])
    group = next((item for item in groups if item.get('name') == GROUP), None)
    all_names = {
        proxy.get('name')
        for proxy in data.get('proxies') or []
        if isinstance(proxy, dict)
    }
    if group is not None:
        group['proxies'] = [
            proxy.get('name')
            for proxy in imported
            if not is_disabled(proxy.get('name'), disabled) and proxy.get('name') in all_names
        ]
    else:
        for gname in ('PROXY', 'AUTO'):
            grp = next((item for item in groups if item.get('name') == gname), None)
            if grp is not None:
                current_members = list(grp.get('proxies') or [])
                for proxy in imported:
                    pname = proxy.get('name')
                    if pname and not is_disabled(pname, disabled) and pname in all_names and pname not in current_members:
                        if gname == 'AUTO' and is_auto_excluded(pname):
                            continue
                        current_members.append(pname)
                grp['proxies'] = current_members

    kept = []
    removed = 0
    # Injected subscription nodes carry a ``[<sub>] `` name prefix. Any one that
    # is present in the live config but no longer in the active vps-import
    # whitelist is an orphan (deleted/renamed/refreshed-away subscription); drop
    # it from the proxies list so the delete actually propagates to the live
    # config instead of persisting in PROXY across reloads. Self-built nodes
    # share the bracket syntax but are hand-managed, so ``[自建] `` is exempt.
    imported_names = {p.get('name') for p in imported if isinstance(p, dict) and p.get('name')}
    injected_prefix = re.compile(r'^\[[^\]]+\] ')
    for proxy in data.get('proxies') or []:
        if not isinstance(proxy, dict):
            continue
        p_name = proxy.get('name')
        p_name = p_name if isinstance(p_name, str) else (str(p_name) if p_name is not None else '')
        orphan = (
            bool(injected_prefix.match(p_name))
            and not p_name.startswith(SELF_TAG)
            and p_name not in imported_names
            and not is_disabled(p_name, disabled)
        )
        if not p_name or is_disabled(p_name, disabled) or is_third_party_or_blocked(p_name) or orphan:
            removed += 1
        else:
            kept.append(proxy)
    data['proxies'] = kept

    kept_name_set = {p['name'] for p in kept if isinstance(p, dict) and p.get('name')}
    group_name_set = {g.get('name') for g in groups if isinstance(g, dict) and g.get('name')}
    valid_references = kept_name_set | group_name_set | {'DIRECT', 'REJECT', 'GLOBAL'}

    for item in data.get('proxy-groups') or []:
        if isinstance(item, dict):
            g_name = item.get('name')
            cleaned = [
                name for name in (item.get('proxies') or [])
                if name in valid_references and not is_disabled(name, disabled) and not is_third_party_or_blocked(name)
            ]
            if g_name == 'AUTO':
                cleaned = [name for name in cleaned if not is_auto_excluded(name)]
            elif g_name == 'PROXY':
                cleaned = [name for name in cleaned if not any(k in name.lower() for k in ('reverse', '17897', 'pxed-bridge'))]
            elif g_name == 'cpa-clean-egress':
                cleaned = [name for name in cleaned if not any(k in name.lower() for k in ('reverse', '17897'))]
                # 2026-11-02: 家宽优先走 mesh。CF 隧道链路掉线时 fallback 会跳过它
                # 落到国内 Reality 节点(cpa-clean-egress 语义是住宅家宽出口);
                # mesh 与 CF 同一家宽出口但经 easytier 直连更稳, CF 降为次选。
                # 仅对 fallback 形态生效, 不动 config.mac-merged 的 select 形态。
                bare = ('🏠home-win-CF', '🏠home-win-mesh') if item.get('type') == 'fallback' else ('🏠home-win-CF',)
                prefs = tuple(p for p in (home_pref(b, valid_references) for b in bare) if p)
                for pref in prefs:
                    if pref not in cleaned:
                        cleaned.insert(0, pref)
                    elif cleaned[0] != pref:
                        cleaned.remove(pref)
                        cleaned.insert(0, pref)
            if not cleaned:
                cleaned = ['PROXY'] if 'PROXY' in valid_references and g_name != 'PROXY' else ['DIRECT']
            item['proxies'] = cleaned
    return data, len(added), removed


def reload_live() -> int:
    try:
        try:
            from cluster_reload import reload_cluster
        except ImportError:
            clash_dir = str(Path(__file__).resolve().parent)
            if clash_dir not in sys.path:
                sys.path.insert(0, clash_dir)
            from cluster_reload import reload_cluster

        res = reload_cluster(config_path=ROOT / 'config.yaml')
        loc = res['local']
        rem = res['remote']
        print(
            f"cluster_reload: local={loc.get('status')}({loc.get('node')}), "
            f"remote={rem.get('status')}({rem.get('peer_node')}@{rem.get('peer_ip')})"
        )
        if not loc.get('success'):
            raise RuntimeError(f"Local reload failed: {loc.get('error')}")
        return loc.get('status', 204)
    except ImportError:
        pass
    secret_file = ROOT / '.controller-secret'
    secret = secret_file.read_text().strip()
    req = urllib.request.Request(
        'http://127.0.0.1:9090/configs?force=true',
        data=('{"path":"%s"}' % (ROOT / 'config.yaml')).encode('utf-8'),
        method='PUT',
        headers={
            'Authorization': f'Bearer {secret}',
            'Content-Type': 'application/json',
        },
    )
    with urllib.request.urlopen(req, timeout=15) as response:
        return response.status


def main() -> None:
    airport = resolve_airport(ROOT)
    try:
        airport.relative_to(ROOT / 'airports')
    except ValueError:
        print(f'refusing airport path outside {ROOT / "airports"}: {airport}', file=sys.stderr)
        sys.exit(2)
    if not airport.exists():
        print(f'{airport.name}: missing; skip')
        return
    loaded = load_vps_import(airport)
    if loaded is None:
        print(f'{airport.name}: no groups.{VPS_GROUP}; skip (refusing full-file dump)')
        return
    imported, names, pool_proxies = loaded
    if not names:
        print(f'{airport.name}: groups.{VPS_GROUP} empty; skip')
        return
    disabled = load_disabled()
    timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
    changed_live = False
    targets = tuple(
        path for path in (ROOT / 'config.mac-merged.yaml', ROOT / 'config.yaml')
        if path.exists()
    )
    if not targets:
        print('no clash config targets; skip')
        return
    for target in targets:
        data, added, removed = build_data(target, imported, disabled, pool_proxies)
        rendered = yaml.safe_dump(data, allow_unicode=True, sort_keys=False, width=120)
        current = target.read_text()
        if rendered == current:
            print(f'{target.name}: unchanged added=0 removed=0 members={len(names)}')
            continue
        backup = Path(str(target) + f'.pre-local-persist-{timestamp}')
        shutil.copy2(target, backup)
        target.write_text(rendered)
        print(f'{target.name}: changed added={added} removed={removed} members={len(names)}')
        if target.name == 'config.yaml':
            changed_live = True
    if changed_live:
        if not (ROOT / '.controller-secret').exists():
            print('live_reload skipped: missing .controller-secret')
        else:
            print(f'live_reload={reload_live()}')


if __name__ == '__main__':
    main()
