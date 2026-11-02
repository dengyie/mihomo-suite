#!/usr/bin/env python3
"""Persist verified local nodes and an explicit denylist into live Clash configs.

The node file holds proxies plus simple name lists under ``groups``. This
script only fills ``🌐 本机导入`` from ``groups.vps-import``. url-test / PROXY /
Grok / Google strategy stays elsewhere. Unchanged files are not rewritten;
a changed live config is reloaded once through 9090.
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
THIRD_PARTY_PREFIXES = tuple(
    p.strip() for p in os.environ.get('THIRD_PARTY_PREFIXES', 'SUB-,JX-,GL-,JS-,KQ-').split(',') if p.strip()
)
BLOCKED_NAMES = {'续费备用节点', 'PXED-BRIDGE'}


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


def load_vps_import(path: Path) -> tuple[list[dict], list[str]] | None:
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
    return imported, names


def build_data(target: Path, imported: list[dict], disabled: set[str]) -> tuple[dict, int, int]:
    data = yaml.safe_load(target.read_text()) or {}
    proxies = data.get('proxies') or []
    existing = {
        proxy.get('name')
        for proxy in proxies
        if isinstance(proxy, dict)
    }
    added = [
        proxy for proxy in imported
        if proxy.get('name') not in existing and proxy.get('name') not in disabled
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
            if proxy.get('name') not in disabled and proxy.get('name') in all_names
        ]
    else:
        for gname in ('PROXY', 'AUTO'):
            grp = next((item for item in groups if item.get('name') == gname), None)
            if grp is not None:
                current_members = list(grp.get('proxies') or [])
                for proxy in imported:
                    pname = proxy.get('name')
                    if pname and pname not in disabled and pname in all_names and pname not in current_members:
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
    # config instead of persisting in PROXY across reloads.
    imported_names = {p.get('name') for p in imported if isinstance(p, dict) and p.get('name')}
    injected_prefix = re.compile(r'^\[[^\]]+\] ')
    for proxy in data.get('proxies') or []:
        if not isinstance(proxy, dict):
            continue
        p_name = proxy.get('name')
        p_name = p_name if isinstance(p_name, str) else (str(p_name) if p_name is not None else '')
        orphan = bool(injected_prefix.match(p_name)) and p_name not in imported_names and p_name not in disabled
        if not p_name or p_name in disabled or is_third_party_or_blocked(p_name) or orphan:
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
                if name in valid_references and name not in disabled and not is_third_party_or_blocked(name)
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
                prefs = ('🏠home-win-CF', '🏠home-win-mesh') if item.get('type') == 'fallback' else ('🏠home-win-CF',)
                for pref in prefs:
                    if pref in valid_references and pref not in cleaned:
                        cleaned.insert(0, pref)
                    elif pref in cleaned and cleaned[0] != pref:
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
    imported, names = loaded
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
        data, added, removed = build_data(target, imported, disabled)
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
