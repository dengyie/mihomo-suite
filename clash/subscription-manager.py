#!/usr/bin/env python3
"""Subscription Manager for Mihomo / Clash on tebi / macOS.

Manages subscription sources, parses various subscription formats (Clash YAML,
Base64 node lists, proxy URIs: ss, vmess, vless, trojan, hysteria2/hy2),
filters out non-proxy announcement nodes, isolates names with subscription prefixes,
tracks metadata in subscriptions/meta.json, caches raw subscription bodies,
and aggregates active proxies into airports/airport-merged-sub.yaml with file locking
and atomic writes.
"""
from __future__ import annotations

import argparse
import base64
import errno
import fcntl
import hashlib
import http.client
import ipaddress
import json
import logging
import os
import re
import secrets
import socket
import ssl
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

import yaml

# ROOT configuration supporting CLASH_ROOT environment variable
CLASH_ROOT_ENV = os.environ.get('CLASH_ROOT')
ROOT = Path(CLASH_ROOT_ENV).resolve() if CLASH_ROOT_ENV else Path('/personal/clash')

META_FILE = ROOT / 'subscriptions/meta.json'
RAW_CACHE_DIR = ROOT / 'subscriptions/raw'
MERGED_OUTPUT_FILE = ROOT / 'airports/airport-merged-sub.yaml'
LOCK_FILE = ROOT / 'subscriptions/.subscription.lock'
DISABLED_NODES_FILE = ROOT / 'airports/disabled-nodes.txt'
CLIENT_EXPORT_TOKEN_FILE = ROOT / 'subscriptions/client-export.token'
LOCAL_NODES_FILE = ROOT / 'airports/local-nodes.yaml'
CLIENT_EXPORT_FILE = ROOT / 'airports/mango-clash.yaml'
CLIENT_EXPORT_META_FILE = ROOT / 'airports/mango-clash.meta.json'
CLIENT_EXPORT_TOKEN_MODE = 0o640
CLIENT_EXPORT_RENDER_REV = '8'
CLIENT_BUILTIN_OUTBOUNDS = frozenset({
    'DIRECT', 'REJECT', 'REJECT-DROP', 'PASS', 'COMPATIBLE', 'GLOBAL',
})
_LOG = logging.getLogger('mango-clash-export')

# Client Clash export: DNS bootstrap that avoids TUN + fake-ip deadlock.
CLIENT_DNS = {
    'enable': True,
    'ipv6': False,
    'use-hosts': False,
    'enhanced-mode': 'fake-ip',
    'fake-ip-range': '198.18.0.1/16',
    'default-nameserver': ['223.5.5.5', '119.29.29.29', '1.1.1.1'],
    'proxy-server-nameserver': [
        'https://doh.pub/dns-query',
        'https://dns.alidns.com/dns-query',
    ],
    'nameserver': [
        'https://223.5.5.5/dns-query',
        'https://doh.pub/dns-query',
    ],
    'fake-ip-filter': [
        '*.lan',
        '*.local',
        '*.localdomain',
        'localhost',
        '+.argotunnel.com',
        '+.mangoq.ccwu.cc',
        '+.cc.cd',
    ],
}

# 2026-10-01: hosts 钉死已移除（纯 DoH）。
# 回退: 见 clash 规则.md 十九(2026-10-01 已回退 hosts 钉死方案)。如需重演旧方案，恢复 CLIENT_HOSTS_IPV6 常量并在 CLIENT_DNS 还原 use-hosts/ipv6。


# 2026-10-10: 国内主流音视频会议/协作直连白名单
# 避免下方 STUN/TURN 标准端口规则误将国内合法会议软件（腾讯会议、飞书、钉钉、企业微信等）导向海外代理，保障国内会议超低延迟直连。
CLIENT_DOMESTIC_MEDIA_RULES = [
    'DOMAIN-SUFFIX,meeting.tencent.com,DIRECT',
    'DOMAIN-SUFFIX,voip.qq.com,DIRECT',
    'DOMAIN-SUFFIX,feishu.cn,DIRECT',
    'DOMAIN-SUFFIX,dingtalk.com,DIRECT',
    'DOMAIN-SUFFIX,work.weixin.qq.com,DIRECT',
]

# 2026-10-10: WebRTC STUN / UDP 分流规则（防真实公网 IP 泄漏，全端统一源端下发）
# 优先于 DIRECT_RULES（特别是 cloudflare.com），将公网 STUN 域名与 RFC 5389/5766 标准端口（3478, 5349, 19302-19305）导向 PROXY，
# 消除 WebRTC 在 TUN 模式下直接通过 UDP 反射真实家宽/公网 IP 的隐患。
CLIENT_STUN_RULES = [
    'DOMAIN,stun.cloudflare.com,PROXY',
    'DOMAIN-KEYWORD,stun,PROXY',
    'DST-PORT,3478,PROXY',
    'DST-PORT,5349,PROXY',
    'DST-PORT,19302-19305,PROXY',
]

CLIENT_DIRECT_RULES = [
    'DOMAIN-SUFFIX,argotunnel.com,DIRECT',
    'DOMAIN-SUFFIX,cloudflare.com,DIRECT',
    'DOMAIN-SUFFIX,mangoqwq.com,DIRECT',
    'DOMAIN-SUFFIX,kryptex.network,DIRECT',
    'DOMAIN-SUFFIX,kryptex.com,DIRECT',
    'IP-CIDR,104.208.65.233/32,DIRECT,no-resolve',
    'IP-CIDR,35.212.179.13/32,DIRECT,no-resolve',
    'IP-CIDR,51.83.6.5/32,DIRECT,no-resolve',
    'IP-CIDR,45.202.199.205/32,DIRECT,no-resolve',
    'GEOIP,LAN,DIRECT,no-resolve',
]

GOOGLE_GROUP = '🎯Google'
CLIENT_GOOGLE_RULES = [
    'DOMAIN,accounts.google.com,' + GOOGLE_GROUP,
    'DOMAIN,accounts.youtube.com,' + GOOGLE_GROUP,
    'DOMAIN,oauth2.googleapis.com,' + GOOGLE_GROUP,
    'DOMAIN,www.googleapis.com,' + GOOGLE_GROUP,
    'DOMAIN,apis.google.com,' + GOOGLE_GROUP,
    'DOMAIN,ssl.gstatic.com,' + GOOGLE_GROUP,
    'DOMAIN,www.gstatic.com,' + GOOGLE_GROUP,
    'DOMAIN,lh3.googleusercontent.com,' + GOOGLE_GROUP,
    'DOMAIN-SUFFIX,google.com,' + GOOGLE_GROUP,
    'DOMAIN-SUFFIX,google.com.hk,' + GOOGLE_GROUP,
    'DOMAIN-SUFFIX,googleapis.com,' + GOOGLE_GROUP,
    'DOMAIN-SUFFIX,gstatic.com,' + GOOGLE_GROUP,
    'DOMAIN-SUFFIX,googleusercontent.com,' + GOOGLE_GROUP,
    'DOMAIN-SUFFIX,ggpht.com,' + GOOGLE_GROUP,
    'DOMAIN-SUFFIX,googlevideo.com,' + GOOGLE_GROUP,
    'DOMAIN-SUFFIX,youtube.com,' + GOOGLE_GROUP,
    'DOMAIN-SUFFIX,youtu.be,' + GOOGLE_GROUP,
    'DOMAIN-SUFFIX,gvt0.com,' + GOOGLE_GROUP,
    'DOMAIN-SUFFIX,gvt1.com,' + GOOGLE_GROUP,
    'DOMAIN-SUFFIX,gvt2.com,' + GOOGLE_GROUP,
    'DOMAIN-SUFFIX,gvt3.com,' + GOOGLE_GROUP,
    'DOMAIN-SUFFIX,gmail.com,' + GOOGLE_GROUP,
]
CLIENT_FINAL_RULES = ['MATCH,PROXY']

# 2026-10-01: MangoCF 橙标域名直连优先+故障回落(源端统一下发; 机制/教训全文见 clash 规则.md §十九)。
# fallback 按序取第一个存活成员: DIRECT 探针 1.5s 内通=直连; v4 波浪判死→AUTO(自动最快存活节点)→PROXY(手选兜底), 恢复自动切回。
# 探针必须与被保护域同 CF IP 段(GFW 波浪按段打击, cloudflare.com 的 104.16 段测不出 mangoqwq 104.21/172.67 段的波浪);
# favicon 走 CF 边缘缓存(cf-cache-status HIT, max-age=14400), 与 hub 源站解耦。
MANGO_CF_GROUP_NAME = 'MangoCF'
CLIENT_MANGO_CF_GROUP = {
    'name': MANGO_CF_GROUP_NAME,
    'type': 'fallback',
    'proxies': ['DIRECT', 'AUTO', 'PROXY'],
    'url': 'https://vps.mangoqwq.com/favicon.ico',
    'interval': 5,
    'timeout': 1000,
    'lazy': False,
}
# 2026-10-01(下午): 白名单改为例外清单+全域 suffix——download.mangoqwq.com 等新增子域不在 13 条名单内仍吃 v4 波浪;
# 现仅 ssh-*/frp/doh/home-node/cpa.us(灰云)/check(本机 hosts 服务) 保持 DIRECT, 其余 *.mangoqwq.com 全部进 MangoCF。
CLIENT_MANGO_CF_EXCEPT_RULES = [
    'DOMAIN,%s.mangoqwq.com,DIRECT' % d
    for d in ('ssh-tebi', 'ssh-pxed', 'ssh-home', 'ssh-laptop', 'frp', 'doh', 'doh-demo', 'home-node', 'cpa.us', 'check', 'check-api')
]
CLIENT_MANGO_CF_RULES = CLIENT_MANGO_CF_EXCEPT_RULES + ['DOMAIN-SUFFIX,mangoqwq.com,%s' % MANGO_CF_GROUP_NAME]
_US_GOOGLE_NAME = re.compile(r'美国_BGP|北美洲】美国\d+原生')
LOCAL_GROUP_VPS = 'vps-import'
LOCAL_GROUP_GOOGLE = 'google'
LOCAL_GROUP_GROK = 'grok'


def _is_us_google_node(name: str) -> bool:
    """Fallback US-Google name filter when local-nodes.yaml has no groups.google."""
    n = str(name or '').strip()
    if not n:
        return False
    low = n.lower()
    if 'azure' in low or 'googlevps' in low or n.startswith('GVPS') or '香港' in n:
        return False
    return _US_GOOGLE_NAME.search(n) is not None


def normalize_simple_groups(raw: Any) -> Dict[str, List[str]]:
    """Keep only name lists. Clash url-test/select fields are ignored."""
    groups: Dict[str, List[str]] = {}
    if not isinstance(raw, dict):
        return groups
    for key, val in raw.items():
        label = str(key or '').strip()
        if not label:
            continue
        items = val
        if isinstance(val, dict):
            items = val.get('proxies')
        if not isinstance(items, list):
            continue
        names: List[str] = []
        seen: Set[str] = set()
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


def prune_simple_groups(groups: Dict[str, List[str]], kept_names: Set[str]) -> Dict[str, List[str]]:
    pruned: Dict[str, List[str]] = {}
    for label, names in groups.items():
        pruned[label] = [n for n in names if n in kept_names]
    return pruned


def resolve_simple_group(
    groups: Dict[str, List[str]],
    label: str,
    available: Set[str],
    fallback: Optional[List[str]] = None,
) -> List[str]:
    if label in groups:
        return [n for n in groups[label] if n in available]
    if fallback is not None:
        return [n for n in fallback if n in available]
    return []


def drop_unresolved_dialer_proxies(proxies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Drop chain nodes whose dialer-proxy is not in this same proxy list.

    Clash Meta refuses the whole YAML when a remaining proxy points at a
    missing dialer. Walk until stable so A→B→missing drops both A and B.
    """
    kept = [p for p in proxies if isinstance(p, dict)]
    builtin = {'DIRECT', 'REJECT', 'COMPATIBLE'}
    while True:
        names = {
            str(p.get('name') or '').strip()
            for p in kept
            if str(p.get('name') or '').strip()
        }
        nxt: List[Dict[str, Any]] = []
        dropped = False
        for proxy in kept:
            dialer = str(proxy.get('dialer-proxy') or proxy.get('dialer_proxy') or '').strip()
            if dialer and dialer not in names and dialer not in builtin:
                dropped = True
                continue
            nxt.append(proxy)
        kept = nxt
        if not dropped:
            return kept


class ClientExportInvalid(ValueError):
    """Rendered client YAML failed validation and no last-good file exists."""

    def __init__(self, errors: List[str]):
        self.errors = [str(e) for e in errors if str(e).strip()]
        preview = '; '.join(self.errors[:8]) or 'unknown validation error'
        super().__init__(f'client yaml invalid: {preview}')


def _kernel_test_client_yaml(text: str, kernel_bin: Path, workdir: Path) -> Optional[str]:
    """Run ``mihomo -t`` on a candidate. None means pass or binary missing."""
    if not kernel_bin.exists():
        return None
    parent = workdir / 'airports' if (workdir / 'airports').is_dir() else workdir
    parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix='mango-clash-test-', suffix='.yaml', dir=str(parent))
    try:
        os.write(fd, text.encode('utf-8'))
        os.close(fd)
        fd = -1
        try:
            os.chmod(name, 0o600)
        except OSError:
            pass
        res = subprocess.run(
            [str(kernel_bin), '-t', '-d', str(workdir), '-f', name],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
        )
        if res.returncode == 0:
            return None
        msg = (res.stderr or res.stdout or f'exit {res.returncode}').strip()
        return f'mihomo -t: {msg[:500]}'
    except Exception as e:
        return f'mihomo -t: {e}'
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            os.remove(name)
        except OSError:
            pass


def _rule_outbound(rule: Any) -> Optional[str]:
    if not isinstance(rule, str):
        return None
    parts = [p.strip() for p in rule.split(',') if p.strip()]
    if len(parts) < 2:
        return None
    if parts[-1].lower() == 'no-resolve' and len(parts) >= 3:
        return parts[-2]
    return parts[-1]


def validate_client_clash_yaml(
    text: str,
    *,
    kernel_bin: Optional[Path] = None,
    workdir: Optional[Path] = None,
) -> List[str]:
    """Structural (and optional kernel) checks. Empty list means publishable.

    Catches the class of errors Clash Verge treats as a failed profile test:
    dangling dialer-proxy, missing group members, duplicate names, empty
    url-test pools. A failed check must not replace last-good bytes.
    """
    errors: List[str] = []
    try:
        data = yaml.safe_load(text) if text and text.strip() else None
    except Exception as e:
        return [f'yaml-parse: {e}']
    if not isinstance(data, dict):
        return ['yaml-parse: not a mapping']

    proxies = data.get('proxies')
    if not isinstance(proxies, list) or not proxies:
        errors.append('proxies: empty')
        proxies = proxies if isinstance(proxies, list) else []

    names: List[str] = []
    seen: Set[str] = set()
    for i, proxy in enumerate(proxies):
        if not isinstance(proxy, dict):
            errors.append(f'proxies[{i}]: not a mapping')
            continue
        name = str(proxy.get('name') or '').strip()
        if not name:
            errors.append(f'proxies[{i}]: missing name')
            continue
        if name in seen:
            errors.append(f'proxies: duplicate name {name}')
        if name in CLIENT_BUILTIN_OUTBOUNDS:
            errors.append(f'proxy {name}: collides with builtin')
        seen.add(name)
        names.append(name)
        if not str(proxy.get('type') or '').strip():
            errors.append(f'proxy {name}: missing type')

    name_set = set(names)
    for proxy in proxies:
        if not isinstance(proxy, dict):
            continue
        name = str(proxy.get('name') or '').strip() or '?'
        dialer = str(proxy.get('dialer-proxy') or proxy.get('dialer_proxy') or '').strip()
        if dialer and dialer not in name_set and dialer not in CLIENT_BUILTIN_OUTBOUNDS:
            errors.append(f'proxy {name}: dialer-proxy {dialer} not found')

    groups = data.get('proxy-groups') or []
    if not isinstance(groups, list):
        errors.append('proxy-groups: not a list')
        groups = []
    group_names: Set[str] = set()
    for i, group in enumerate(groups):
        if not isinstance(group, dict):
            errors.append(f'proxy-groups[{i}]: not a mapping')
            continue
        gname = str(group.get('name') or '').strip()
        if not gname:
            errors.append(f'proxy-groups[{i}]: missing name')
            continue
        if gname in group_names:
            errors.append(f'duplicate group {gname}')
        if gname in CLIENT_BUILTIN_OUTBOUNDS:
            errors.append(f'group {gname}: collides with builtin')
        if gname in name_set:
            errors.append(f'group {gname}: collides with proxy')
        group_names.add(gname)
    allowed = name_set | group_names | CLIENT_BUILTIN_OUTBOUNDS
    for i, group in enumerate(groups):
        if not isinstance(group, dict):
            continue
        gname = str(group.get('name') or '').strip() or f'groups[{i}]'
        members = group.get('proxies') or []
        if not isinstance(members, list) or not members:
            errors.append(f'group {gname}: empty proxies')
            continue
        for member in members:
            label = str(member or '').strip()
            if not label:
                errors.append(f'group {gname}: empty member')
            elif label not in allowed:
                errors.append(f'group {gname}: member {label} not found')

    rules = data.get('rules')
    if rules is not None:
        if not isinstance(rules, list) or not rules:
            errors.append('rules: empty')
        else:
            for i, rule in enumerate(rules):
                target = _rule_outbound(rule)
                if not target:
                    errors.append(f'rules[{i}]: missing outbound')
                elif target not in allowed:
                    errors.append(f'rules[{i}]: outbound {target} not found')

    if errors:
        return errors
    if kernel_bin is not None:
        kernel_err = _kernel_test_client_yaml(text, kernel_bin, workdir or Path('.'))
        if kernel_err:
            errors.append(kernel_err)
    return errors


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def sha256_file(path: Path) -> str:
    if not path.exists() or not path.is_file():
        return 'missing'
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _export_warn(msg: str) -> None:
    _LOG.warning(msg)
    print(msg, flush=True)


# Clash Verge TUN (gvisor + fake-ip). Verge still needs enable_tun_mode in
# verge.yaml; this block is what the kernel actually loads from the profile.
CLIENT_TUN = {
    'enable': True,
    'stack': 'gvisor',
    'dns-hijack': ['any:53'],
    'auto-route': True,
    'auto-detect-interface': True,
}

FETCH_MAX_BYTES = 8 * 1024 * 1024
NODE_PROBE_TIMEOUT_SEC = 1.5
NODE_PROBE_MAX_WORKERS = 16
NODE_PROBE_MAX_CANDIDATES = 200
# UDP-only outbound cannot be TCP-probed; keep them when expanding the node file.
# Parser emits type=hysteria2 for both hysteria2:// and hy2://; hy2 stays as a belt.
UDP_NODE_TYPES = frozenset({'hysteria', 'hysteria2', 'hy2', 'tuic', 'wireguard'})
PROBE_REASON_SSRF = 'ssrf-skip'


def client_allow_lan() -> bool:
    """Client export binds mixed-port on LAN only when CLIENT_ALLOW_LAN=1.

    Default false: TUN already covers the local machine; LAN listen is a
    separate exposure and must not ship on by default.
    """
    return os.environ.get('CLIENT_ALLOW_LAN', '').strip().lower() in ('1', 'true', 'yes')

# Default regex pattern to filter out announcement / non-functional nodes
DEFAULT_EXCLUDE_FILTER = r'(剩余流量|更新日期|官网|套餐|重置|到期|过期|公告|流量|时间|群|客服|traffic|expire|reset|website|notice)'


def safe_atomic_write(target_path: Path, content: str, encoding: str = 'utf-8', mode: int = 0o660) -> None:
    """Atomically write content to target_path using unique temporary file and safe permissions."""
    target_path.parent.mkdir(parents=True, exist_ok=True)
    tf = tempfile.NamedTemporaryFile('w', dir=target_path.parent, delete=False, encoding=encoding)
    try:
        tf.write(content)
        tf.flush()
        try:
            os.fchmod(tf.fileno(), mode)
        except OSError:
            pass
        tf.close()
        os.replace(tf.name, target_path)
    except Exception:
        if os.path.exists(tf.name):
            try:
                os.remove(tf.name)
            except OSError:
                pass
        raise


# Group name for auto-mounted subscription proxies
SUB_GROUP_NAME = '🌐 订阅导入'
GENERIC_GROUP_NAMES = {'PROXY', '🚀 节点选择', '🎯 全球直连', '节点选择', 'Proxy', 'proxy'}


def _ip_is_blocked(ip_obj: ipaddress._BaseAddress) -> bool:
    return bool(
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_reserved
        or ip_obj.is_multicast
        or ip_obj.is_unspecified
    )


def is_safe_public_url(url: str, allow_private: bool = False) -> Tuple[bool, str]:
    """Validate that a URL is a safe HTTP/HTTPS endpoint to prevent SSRF attacks.

    Always requires http/https. Resolves the hostname and rejects private,
    loopback, link-local, reserved, multicast, and unspecified addresses unless
    ``allow_private`` is True or ``ALLOW_PRIVATE_SUBSCRIPTIONS=1``.
    """
    allow_private = allow_private or os.environ.get('ALLOW_PRIVATE_SUBSCRIPTIONS') == '1'

    if not url or not isinstance(url, str):
        return False, "Invalid or empty URL"

    try:
        parsed = urllib.parse.urlsplit(url)
    except Exception as e:
        return False, f"Failed to parse URL: {e}"

    scheme = (parsed.scheme or "").lower()
    if scheme not in ('http', 'https'):
        return False, f"Disallowed URL scheme '{scheme}'. Only http and https are permitted."

    hostname = parsed.hostname
    if not hostname:
        return False, "URL does not contain a valid hostname"

    try:
        ip_obj = ipaddress.ip_address(hostname.strip('[]'))
        if not allow_private and _ip_is_blocked(ip_obj):
            return False, "Disallowed internal/private IP or hostname"
        return True, ""
    except ValueError:
        pass

    try:
        addr_infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
        if not addr_infos:
            return False, f"Could not resolve hostname '{hostname}'"

        for info in addr_infos:
            sockaddr = info[4]
            ip_str = sockaddr[0]
            ip_obj = ipaddress.ip_address(ip_str)
            if not allow_private and _ip_is_blocked(ip_obj):
                return False, "Disallowed internal/private IP or hostname"
    except socket.gaierror as e:
        return False, f"DNS resolution failed for hostname '{hostname}': {e}"
    except Exception as e:
        return False, f"SSRF check error: {e}"

    return True, ""


_HAS_IPV6_ROUTE: Optional[bool] = None


def has_ipv6_route(force_check: bool = False) -> bool:
    """Return True if host has a usable IPv6 route to the public internet."""
    global _HAS_IPV6_ROUTE
    if _HAS_IPV6_ROUTE is not None and not force_check:
        return _HAS_IPV6_ROUTE
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s.connect(('2001:4860:4860::8888', 80))
        s.close()
        _HAS_IPV6_ROUTE = True
    except Exception:
        _HAS_IPV6_ROUTE = False
    return _HAS_IPV6_ROUTE


def _pin_resolved_ip(hostname: str, allow_private: bool) -> str:
    """Return one resolved address for hostname after the SSRF filter.

    Connecting to this IP (with Host/SNI still set to the original hostname)
    closes the DNS-rebinding window between check and connect.
    """
    try:
        ip_obj = ipaddress.ip_address(hostname.strip('[]'))
        if not allow_private and _ip_is_blocked(ip_obj):
            raise ValueError("Disallowed internal/private IP or hostname")
        return hostname.strip('[]')
    except ValueError:
        if hostname.startswith('[') and hostname.endswith(']'):
            pass
        else:
            try:
                ipaddress.ip_address(hostname)
            except ValueError:
                pass

    addr_infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    if not addr_infos:
        raise ValueError(f"Could not resolve hostname '{hostname}'")
    if not has_ipv6_route():
        addr_infos = sorted(addr_infos, key=lambda info: 0 if info[0] == socket.AF_INET else 1)
    for info in addr_infos:
        ip_str = info[4][0]
        ip_obj = ipaddress.ip_address(ip_str)
        if allow_private or not _ip_is_blocked(ip_obj):
            return ip_str
    raise ValueError("Disallowed internal/private IP or hostname")


def _read_capped(resp, limit: int) -> bytes:
    buf = bytearray()
    while True:
        chunk = resp.read(min(65536, max(1, limit - len(buf) + 1)))
        if not chunk:
            break
        buf.extend(chunk)
        if len(buf) > limit:
            raise ValueError(f"Response exceeds size limit ({limit} bytes)")
    return bytes(buf)


def _http_get_pinned(url: str, timeout: int, user_agent: str) -> Tuple[int, dict, bytes, str]:
    """GET url, connecting to a pinned IP. Does not follow redirects."""
    parsed = urllib.parse.urlsplit(url)
    scheme = (parsed.scheme or '').lower()
    hostname = parsed.hostname
    if not hostname:
        raise ValueError("URL does not contain a valid hostname")
    port = parsed.port or (443 if scheme == 'https' else 80)
    path = parsed.path or '/'
    if parsed.query:
        path = path + '?' + parsed.query
    allow_private = os.environ.get('ALLOW_PRIVATE_SUBSCRIPTIONS') == '1'
    pinned_ip = _pin_resolved_ip(hostname, allow_private=allow_private)

    headers = {
        'User-Agent': user_agent,
        'Host': hostname if parsed.port is None else f'{hostname}:{parsed.port}',
        'Accept': '*/*',
        'Connection': 'close',
    }

    if scheme == 'https':
        ctx = ssl.create_default_context()
        conn = http.client.HTTPSConnection(pinned_ip, port, timeout=timeout, context=ctx)

        def _connect_with_sni():
            sock = socket.create_connection((pinned_ip, port), timeout)
            conn.sock = ctx.wrap_socket(sock, server_hostname=hostname)

        conn.connect = _connect_with_sni  # type: ignore[assignment]
    else:
        conn = http.client.HTTPConnection(pinned_ip, port, timeout=timeout)

    try:
        conn.request('GET', path, headers=headers)
        resp = conn.getresponse()
        header_map = {k.lower(): v for k, v in resp.getheaders()}
        body = _read_capped(resp, FETCH_MAX_BYTES)
        return resp.status, header_map, body, pinned_ip
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _http_get_via_proxy(
    url: str,
    proxy_url: str,
    timeout: int,
    user_agent: str,
) -> Tuple[int, dict, bytes]:
    """GET url via an HTTP proxy (e.g. http://127.0.0.1:7897). Does not follow redirects."""
    proxy_clean = (proxy_url or '').strip()
    if proxy_clean and '://' not in proxy_clean:
        proxy_clean = f'http://{proxy_clean}'
    proxy_parsed = urllib.parse.urlsplit(proxy_clean)
    proxy_host = proxy_parsed.hostname or '127.0.0.1'
    proxy_port = proxy_parsed.port or 7897

    parsed = urllib.parse.urlsplit(url)
    scheme = (parsed.scheme or '').lower()
    hostname = parsed.hostname
    if not hostname:
        raise ValueError("URL does not contain a valid hostname")
    port = parsed.port or (443 if scheme == 'https' else 80)
    path = parsed.path or '/'
    if parsed.query:
        path = path + '?' + parsed.query

    headers = {
        'User-Agent': user_agent,
        'Host': hostname if parsed.port is None else f'{hostname}:{parsed.port}',
        'Accept': '*/*',
        'Connection': 'close',
    }

    if scheme == 'https':
        ctx = ssl.create_default_context()
        conn = http.client.HTTPSConnection(proxy_host, proxy_port, timeout=timeout, context=ctx)
        conn.set_tunnel(hostname, port, headers={'User-Agent': user_agent})
    else:
        conn = http.client.HTTPConnection(proxy_host, proxy_port, timeout=timeout)

    try:
        conn.request('GET', path if scheme == 'https' else url, headers=headers)
        resp = conn.getresponse()
        header_map = {k.lower(): v for k, v in resp.getheaders()}
        body = _read_capped(resp, FETCH_MAX_BYTES)
        return resp.status, header_map, body
    finally:
        try:
            conn.close()
        except Exception:
            pass


# ---------------------------------------------------------
# YAML Acceleration (CSafeLoader / CSafeDumper if available)
# ---------------------------------------------------------
_YamlSafeLoader = getattr(yaml, 'CSafeLoader', yaml.SafeLoader)
_YamlSafeDumper = getattr(yaml, 'CSafeDumper', yaml.SafeDumper)


def fast_yaml_load(stream: Any) -> Any:
    """Load YAML stream using C bindings if available for ~7x speedup."""
    if hasattr(stream, 'read'):
        content = stream.read()
    else:
        content = stream
    if not content:
        return None
    return yaml.load(content, Loader=_YamlSafeLoader)


def fast_yaml_dump(data: Any, **kwargs: Any) -> str:
    """Dump YAML document using C bindings if available."""
    kwargs.setdefault('allow_unicode', True)
    kwargs.setdefault('sort_keys', False)
    kwargs.setdefault('width', 120)
    return yaml.dump(data, Dumper=_YamlSafeDumper, **kwargs)


def load_disabled_nodes(disabled_path: Optional[Path] = None) -> Set[str]:
    """Load denylist of confirmed dead/disabled node names from disabled-nodes.txt."""
    path = disabled_path or DISABLED_NODES_FILE
    if not path.exists():
        return set()
    try:
        return {
            line.strip()
            for line in path.read_text(encoding='utf-8', errors='ignore').splitlines()
            if line.strip() and not line.lstrip().startswith('#')
        }
    except Exception:
        return set()


def save_disabled_nodes(names: Set[str], disabled_path: Optional[Path] = None) -> None:
    """Safely append or update disabled nodes list preserving comments."""
    path = disabled_path or DISABLED_NODES_FILE
    existing_lines: List[str] = []
    if path.exists():
        try:
            existing_lines = path.read_text(encoding='utf-8', errors='ignore').splitlines()
        except Exception:
            existing_lines = []

    header_lines = [l for l in existing_lines if l.strip().startswith('#')]
    if not header_lines:
        header_lines = ["# Verified local import denylist; only explicitly confirmed dead nodes."]

    existing_set = {
        l.strip() for l in existing_lines
        if l.strip() and not l.strip().startswith('#')
    }
    merged_set = existing_set | {n.strip() for n in names if n.strip()}
    sorted_names = sorted(merged_set)

    content = "\n".join(header_lines) + "\n" + "\n".join(sorted_names) + "\n"
    safe_atomic_write(path, content)


def reconcile_target_config(
    target_path: Path,
    active_proxies: Optional[List[Dict[str, Any]]] = None,
    disabled_nodes: Optional[Set[str]] = None,
) -> bool:
    """Safely inject active subscription proxies into target config and maintain SUB_GROUP_NAME.
    
    If active_proxies is None, only filters out disabled_nodes without resetting subscription proxies.
    """
    if not target_path.exists():
        return False
    try:
        data = fast_yaml_load(target_path.read_text(encoding='utf-8', errors='ignore')) or {}
        if not isinstance(data, dict):
            return False
    except Exception:
        return False

    proxies = data.get('proxies')
    if not isinstance(proxies, list):
        proxies = []
        data['proxies'] = proxies

    groups = data.get('proxy-groups')
    if not isinstance(groups, list):
        groups = []
        data['proxy-groups'] = groups

    denylist = disabled_nodes if disabled_nodes is not None else load_disabled_nodes()

    # 1. Find previous sub group to identify previous subscription nodes
    sub_group = next((g for g in groups if isinstance(g, dict) and g.get('name') == SUB_GROUP_NAME), None)
    old_sub_node_names: Set[str] = set()
    if sub_group and isinstance(sub_group.get('proxies'), list):
        old_sub_node_names = {str(n) for n in sub_group['proxies']}

    if active_proxies is not None:
        active_proxy_names = [p['name'] for p in active_proxies if isinstance(p, dict) and 'name' in p and p['name'] not in denylist]
        active_name_set = set(active_proxy_names)

        # Filter out stale subscription nodes and denylisted nodes from proxies and add active proxies
        kept_proxies = []
        for p in proxies:
            if isinstance(p, dict):
                p_name = p.get('name')
                if p_name in denylist:
                    continue
                if p_name in old_sub_node_names and p_name not in active_name_set:
                    continue
                if p_name in active_name_set:
                    continue
                kept_proxies.append(p)
        for p in active_proxies:
            if isinstance(p, dict) and p.get('name') not in denylist:
                kept_proxies.append(p)
    else:
        # Only prune denylisted nodes
        kept_proxies = [p for p in proxies if isinstance(p, dict) and p.get('name') not in denylist]
        active_proxy_names = [n for n in old_sub_node_names if n not in denylist]
        active_name_set = set(active_proxy_names)

    # Check if proxies actually changed
    proxies_changed = (proxies != kept_proxies)
    data['proxies'] = kept_proxies

    # 3. Maintain '🌐 订阅导入' proxy group
    groups_changed = False
    if sub_group is None and active_proxies is not None:
        sub_group = {'name': SUB_GROUP_NAME, 'type': 'select', 'proxies': ['DIRECT']}
        groups.append(sub_group)
        groups_changed = True

    if sub_group is not None:
        target_sub_proxies = list(active_proxy_names) if active_proxy_names else ['DIRECT']
        if sub_group.get('proxies') != target_sub_proxies:
            sub_group['proxies'] = target_sub_proxies
            groups_changed = True

    # 4. Clean up stale subscription node names and disabled nodes from all other proxy groups
    stale_sub_nodes = (old_sub_node_names - active_name_set) if active_proxies is not None else set()
    removal_set = stale_sub_nodes | denylist
    for g in groups:
        if isinstance(g, dict) and 'proxies' in g and isinstance(g['proxies'], list):
            if g.get('name') == SUB_GROUP_NAME:
                continue
            cleaned = [n for n in g['proxies'] if n not in removal_set]
            if not cleaned:
                cleaned = ['DIRECT']
            if cleaned != g['proxies']:
                g['proxies'] = cleaned
                groups_changed = True

    # 5. Auto-mount SUB_GROUP_NAME into generic routing groups if present
    for g in groups:
        if isinstance(g, dict) and g.get('name') in GENERIC_GROUP_NAMES:
            g_proxies = g.get('proxies')
            if isinstance(g_proxies, list):
                if SUB_GROUP_NAME not in g_proxies:
                    g_proxies.append(SUB_GROUP_NAME)
                    groups_changed = True

    # Fast short-circuit: if neither proxies nor groups changed, skip expensive dump & disk write!
    if not proxies_changed and not groups_changed:
        return True

    # Write atomically
    rendered = fast_yaml_dump(data)
    safe_atomic_write(target_path, rendered)
    return True


def get_paths(root: Optional[Path] = None) -> Tuple[Path, Path, Path, Path, Path, Path]:
    base = root.resolve() if root else (Path(os.environ.get('CLASH_ROOT')).resolve() if os.environ.get('CLASH_ROOT') else ROOT)
    meta = base / 'subscriptions/meta.json'
    raw_dir = base / 'subscriptions/raw'
    merged = base / 'airports/airport-merged-sub.yaml'
    lock = base / 'subscriptions/.subscription.lock'
    disabled = base / 'airports/disabled-nodes.txt'
    return base, meta, raw_dir, merged, lock, disabled


class SubscriptionLock:
    """Context manager for fcntl file locking."""

    def __init__(self, lock_file: Optional[Path] = None):
        if lock_file is None:
            _, _, _, _, self.lock_path, _ = get_paths()
        else:
            self.lock_path = lock_file
        self.lock_fd = None

    def __enter__(self):
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        self.lock_fd = open(self.lock_path, 'w')
        fcntl.flock(self.lock_fd, fcntl.LOCK_EX)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.lock_fd:
            try:
                fcntl.flock(self.lock_fd, fcntl.LOCK_UN)
            except Exception:
                pass
            try:
                self.lock_fd.close()
            except Exception:
                pass
            self.lock_fd = None


def decode_base64_safely(data: Union[str, bytes]) -> str:
    """Decode base64 string or bytes safely, handling URL-safe variants and missing padding."""
    if isinstance(data, str):
        s = data.strip().replace(' ', '').replace('\n', '').replace('\r', '')
        s_b64 = s.replace('-', '+').replace('_', '/')
        missing_padding = len(s_b64) % 4
        if missing_padding != 0:
            s_b64 += '=' * (4 - missing_padding)
        try:
            return base64.b64decode(s_b64.encode('utf-8')).decode('utf-8', errors='ignore')
        except Exception:
            try:
                return base64.b64decode(s.encode('utf-8')).decode('utf-8', errors='ignore')
            except Exception:
                return ""
    elif isinstance(data, bytes):
        missing_padding = len(data) % 4
        if missing_padding != 0:
            data += b'=' * (4 - missing_padding)
        try:
            return base64.b64decode(data).decode('utf-8', errors='ignore')
        except Exception:
            return ""
    return ""


# ---------------------------------------------------------
# URI Parsers
# ---------------------------------------------------------

def parse_ss_uri(uri: str) -> Optional[Dict[str, Any]]:
    """Parse Shadowsocks URI (ss://...).
    
    Supports:
      - ss://BASE64(method:password@hostname:port)[#tag]
      - ss://BASE64(method:password)@hostname:port[#tag]
      - ss://method:password@hostname:port[#tag]
      - SIP002 query parameters like plugin / plugin-opts
    """
    if not uri.startswith('ss://'):
        return None
    rest = uri[5:]
    tag = ""
    if '#' in rest:
        rest, tag = rest.split('#', 1)
        tag = urllib.parse.unquote(tag).strip()

    method, password, server, port = None, None, None, None
    plugin, plugin_opts = None, {}

    # Case 1: ss://BASE64(...) where decoded part contains method:password@server:port
    if '@' not in rest:
        decoded = decode_base64_safely(rest)
        if '@' in decoded:
            rest = decoded

    if '@' in rest:
        user_info, host_port = rest.rsplit('@', 1)
        if ':' not in user_info:
            user_info = decode_base64_safely(user_info)

        if ':' in user_info:
            method, password = user_info.split(':', 1)
        else:
            return None

        if '?' in host_port:
            host_port, query = host_port.split('?', 1)
            qs = urllib.parse.parse_qs(query)
            if 'plugin' in qs:
                plugin_str = qs['plugin'][0]
                if ';' in plugin_str:
                    plugin_parts = plugin_str.split(';')
                    plugin = plugin_parts[0]
                    for p in plugin_parts[1:]:
                        if '=' in p:
                            k, v = p.split('=', 1)
                            plugin_opts[k] = v
                else:
                    plugin = plugin_str

        if host_port.startswith('['):
            if ']:' in host_port:
                server, port_str = host_port[1:].split(']:', 1)
            else:
                return None
        elif ':' in host_port:
            server, port_str = host_port.split(':', 1)
        else:
            return None

        try:
            port = int(port_str)
        except ValueError:
            return None
    else:
        return None

    if not server or not port or not method or not password:
        return None

    node: Dict[str, Any] = {
        'name': tag or f"SS-{server}:{port}",
        'type': 'ss',
        'server': server,
        'port': port,
        'cipher': method,
        'password': password,
    }
    if plugin:
        node['plugin'] = plugin
        if plugin_opts:
            node['plugin-opts'] = plugin_opts

    return node


def parse_vmess_uri(uri: str) -> Optional[Dict[str, Any]]:
    """Parse VMess URI (vmess://BASE64_JSON)."""
    if not uri.startswith('vmess://'):
        return None
    raw = uri[8:]
    decoded = decode_base64_safely(raw)
    try:
        data = json.loads(decoded)
    except Exception:
        return None

    if not isinstance(data, dict):
        return None

    server = str(data.get('add', '')).strip()
    port_val = data.get('port')
    uuid = str(data.get('id', '')).strip()
    if not server or not port_val or not uuid:
        return None

    try:
        port = int(port_val)
    except (ValueError, TypeError):
        return None

    name = str(data.get('ps', '')).strip() or f"VMess-{server}:{port}"
    alter_id = 0
    try:
        alter_id = int(data.get('aid', 0))
    except (ValueError, TypeError):
        pass

    cipher = str(data.get('scy', 'auto')).strip() or 'auto'
    net = str(data.get('net', 'tcp')).strip().lower()
    tls_val = str(data.get('tls', '')).strip().lower()
    is_tls = tls_val in ('tls', '1', 'true')

    node: Dict[str, Any] = {
        'name': name,
        'type': 'vmess',
        'server': server,
        'port': port,
        'uuid': uuid,
        'alterId': alter_id,
        'cipher': cipher,
        'network': net,
    }

    if is_tls:
        node['tls'] = True
        sni = str(data.get('sni', data.get('host', ''))).strip()
        if sni:
            node['servername'] = sni

    path = str(data.get('path', '')).strip()
    host = str(data.get('host', '')).strip()

    if net == 'ws':
        ws_opts: Dict[str, Any] = {}
        if path:
            ws_opts['path'] = path
        if host:
            ws_opts['headers'] = {'Host': host}
        if ws_opts:
            node['ws-opts'] = ws_opts
    elif net == 'grpc':
        grpc_opts: Dict[str, Any] = {}
        service_name = str(data.get('path', data.get('serviceName', ''))).strip()
        if service_name:
            grpc_opts['grpc-service-name'] = service_name
        if grpc_opts:
            node['grpc-opts'] = grpc_opts
    elif net == 'h2' or net == 'http':
        h2_opts: Dict[str, Any] = {}
        if path:
            h2_opts['path'] = [path] if isinstance(path, str) else path
        if host:
            h2_opts['host'] = [host] if isinstance(host, str) else host
        if h2_opts:
            node['h2-opts'] = h2_opts

    return node


def parse_vless_uri(uri: str) -> Optional[Dict[str, Any]]:
    """Parse VLESS URI (vless://uuid@host:port?query#tag)."""
    if not uri.startswith('vless://'):
        return None
    try:
        u = urllib.parse.urlsplit(uri)
    except Exception:
        return None

    uuid = u.username
    server = u.hostname
    port = u.port
    tag = urllib.parse.unquote(u.fragment).strip() if u.fragment else ""

    if not uuid or not server or not port:
        return None

    qs = urllib.parse.parse_qs(u.query)
    security = qs.get('security', [''])[0].lower()
    net = qs.get('type', ['tcp'])[0].lower()
    sni = qs.get('sni', [''])[0]
    flow = qs.get('flow', [''])[0]
    pbk = qs.get('pbk', [''])[0]
    sid = qs.get('sid', [''])[0]
    fp = qs.get('fp', [''])[0]

    node: Dict[str, Any] = {
        'name': tag or f"VLESS-{server}:{port}",
        'type': 'vless',
        'server': server,
        'port': port,
        'uuid': uuid,
        'network': net,
    }

    if flow:
        node['flow'] = flow

    if security in ('tls', 'reality'):
        node['tls'] = True
        if sni:
            node['servername'] = sni
        if fp:
            node['client-fingerprint'] = fp

        if security == 'reality':
            reality_opts: Dict[str, Any] = {}
            if pbk:
                reality_opts['public-key'] = pbk
            if sid:
                reality_opts['short-id'] = sid
            if reality_opts:
                node['reality-opts'] = reality_opts

    path = qs.get('path', [''])[0]
    host = qs.get('host', [''])[0]
    service_name = qs.get('serviceName', [''])[0]

    if net == 'ws':
        ws_opts: Dict[str, Any] = {}
        if path:
            ws_opts['path'] = path
        if host:
            ws_opts['headers'] = {'Host': host}
        if ws_opts:
            node['ws-opts'] = ws_opts
    elif net == 'grpc':
        grpc_opts: Dict[str, Any] = {}
        g_name = service_name or path
        if g_name:
            grpc_opts['grpc-service-name'] = g_name
        if grpc_opts:
            node['grpc-opts'] = grpc_opts

    return node


def parse_trojan_uri(uri: str) -> Optional[Dict[str, Any]]:
    """Parse Trojan URI (trojan://password@host:port?query#tag)."""
    if not uri.startswith('trojan://'):
        return None
    try:
        u = urllib.parse.urlsplit(uri)
    except Exception:
        return None

    password = u.username or u.password
    server = u.hostname
    port = u.port
    tag = urllib.parse.unquote(u.fragment).strip() if u.fragment else ""

    if not password or not server or not port:
        return None

    qs = urllib.parse.parse_qs(u.query)
    sni = qs.get('sni', qs.get('peer', ['']))[0]
    net = qs.get('type', ['tcp'])[0].lower()
    alpn = qs.get('alpn', [])

    node: Dict[str, Any] = {
        'name': tag or f"Trojan-{server}:{port}",
        'type': 'trojan',
        'server': server,
        'port': port,
        'password': password,
    }

    if sni:
        node['sni'] = sni
    if alpn:
        node['alpn'] = alpn[0].split(',') if len(alpn) == 1 and ',' in alpn[0] else alpn

    path = qs.get('path', [''])[0]
    host = qs.get('host', [''])[0]
    if net == 'ws':
        node['network'] = 'ws'
        ws_opts: Dict[str, Any] = {}
        if path:
            ws_opts['path'] = path
        if host:
            ws_opts['headers'] = {'Host': host}
        if ws_opts:
            node['ws-opts'] = ws_opts
    elif net == 'grpc':
        node['network'] = 'grpc'
        service_name = qs.get('serviceName', [path])[0]
        if service_name:
            node['grpc-opts'] = {'grpc-service-name': service_name}

    return node


def parse_hysteria2_uri(uri: str) -> Optional[Dict[str, Any]]:
    """Parse Hysteria2 / hy2 URI (hysteria2://pass@host:port?query#tag or hy2://...)."""
    if not (uri.startswith('hysteria2://') or uri.startswith('hy2://')):
        return None
    norm_uri = uri
    if uri.startswith('hy2://'):
        norm_uri = 'hysteria2://' + uri[6:]

    try:
        u = urllib.parse.urlsplit(norm_uri)
    except Exception:
        return None

    auth = u.username or u.password
    server = u.hostname
    port = u.port
    tag = urllib.parse.unquote(u.fragment).strip() if u.fragment else ""

    if not auth or not server or not port:
        return None

    qs = urllib.parse.parse_qs(u.query)
    sni = qs.get('sni', [''])[0]
    obfs = qs.get('obfs', [''])[0]
    obfs_password = qs.get('obfs-password', [''])[0]
    insecure = qs.get('insecure', ['0'])[0] in ('1', 'true')

    node: Dict[str, Any] = {
        'name': tag or f"Hy2-{server}:{port}",
        'type': 'hysteria2',
        'server': server,
        'port': port,
        'password': auth,
    }

    if sni:
        node['sni'] = sni
    if insecure:
        node['skip-cert-verify'] = True
    if obfs:
        node['obfs'] = obfs
        if obfs_password:
            node['obfs-password'] = obfs_password

    return node


def parse_proxy_uri(line: str) -> Optional[Dict[str, Any]]:
    """Dispatch raw URI string to corresponding protocol parser."""
    line = line.strip()
    if not line:
        return None
    if line.startswith('ss://'):
        return parse_ss_uri(line)
    elif line.startswith('vmess://'):
        return parse_vmess_uri(line)
    elif line.startswith('vless://'):
        return parse_vless_uri(line)
    elif line.startswith('trojan://'):
        return parse_trojan_uri(line)
    elif line.startswith('hysteria2://') or line.startswith('hy2://'):
        return parse_hysteria2_uri(line)
    return None


def parse_raw_node_list(text: str) -> List[Dict[str, Any]]:
    """Parse text which could be a Base64 blob or multi-line list of proxy URIs."""
    if not text or not text.strip():
        return []

    stripped = text.strip()
    is_plain_uris = any(stripped.startswith(prefix) for prefix in ('ss://', 'vmess://', 'vless://', 'trojan://', 'hy2://', 'hysteria2://'))
    is_plain_yaml = 'proxies:' in stripped or 'Proxy:' in stripped

    lines_to_process = []
    if not is_plain_uris and not is_plain_yaml:
        decoded = decode_base64_safely(stripped)
        if decoded and any(p in decoded for p in ('://', 'proxies:')):
            lines_to_process = decoded.splitlines()
        else:
            lines_to_process = stripped.splitlines()
    else:
        lines_to_process = stripped.splitlines()

    joined_text = '\n'.join(lines_to_process)
    if 'proxies:' in joined_text or 'Proxy:' in joined_text:
        try:
            yaml_data = fast_yaml_load(joined_text)
            if isinstance(yaml_data, dict):
                proxies = yaml_data.get('proxies') or yaml_data.get('Proxy')
                if isinstance(proxies, list):
                    return [p for p in proxies if isinstance(p, dict) and 'name' in p and 'type' in p]
        except Exception:
            pass

    nodes: List[Dict[str, Any]] = []
    for line in lines_to_process:
        line = line.strip()
        if not line:
            continue
        parsed = parse_proxy_uri(line)
        if parsed:
            nodes.append(parsed)

    return nodes


def parse_subscription_content(content: str) -> List[Dict[str, Any]]:
    """Parse raw subscription content (Clash YAML, Base64 list, or raw URI lines)."""
    if not content or not content.strip():
        return []

    try:
        data = fast_yaml_load(content)
        if isinstance(data, dict):
            proxies = data.get('proxies') or data.get('Proxy')
            if isinstance(proxies, list) and len(proxies) > 0:
                valid = [p for p in proxies if isinstance(p, dict) and 'name' in p and 'type' in p]
                if valid:
                    return valid
    except Exception:
        pass

    return parse_raw_node_list(content)


def filter_nodes(nodes: List[Dict[str, Any]], exclude_pattern: Optional[str] = None) -> List[Dict[str, Any]]:
    """Filter out announcement, non-proxy, and matching nodes."""
    pattern_str = exclude_pattern if exclude_pattern is not None else DEFAULT_EXCLUDE_FILTER
    compiled = re.compile(pattern_str, re.IGNORECASE) if pattern_str else None

    valid_nodes: List[Dict[str, Any]] = []
    for node in nodes:
        if not isinstance(node, dict):
            continue
        name = str(node.get('name', '')).strip()
        if not name:
            continue

        if compiled and compiled.search(name):
            continue

        if not node.get('server') or not node.get('port') or not node.get('type'):
            continue

        valid_nodes.append(node)

    return valid_nodes


def apply_node_name_prefix(nodes: List[Dict[str, Any]], sub_name: str) -> List[Dict[str, Any]]:
    """Add sub_name prefix to avoid name collision between subscriptions."""
    prefix = f"[{sub_name}] "
    renamed_nodes = []
    for node in nodes:
        item = dict(node)
        orig_name = str(item.get('name', '')).strip()
        if not orig_name.startswith(prefix):
            item['name'] = f"{prefix}{orig_name}"
        renamed_nodes.append(item)
    return renamed_nodes


def _node_server_port(node: Dict[str, Any]) -> Tuple[Optional[str], Optional[int]]:
    server = str(node.get('server') or '').strip()
    if not server:
        return None, None
    try:
        port = int(node.get('port') or 0)
    except (TypeError, ValueError):
        return server, None
    if port <= 0 or port > 65535:
        return server, None
    return server, port


def _node_endpoint_key(node: Dict[str, Any]) -> Tuple[str, str, Optional[int]]:
    """Stable identity for prune writeback: name + server + port."""
    name = str(node.get('name') or '').strip()
    server, port = _node_server_port(node)
    return name, str(server or ''), port


def _cap_probe_candidates(
    nodes: List[Dict[str, Any]],
    limit: Optional[int] = None,
) -> Tuple[List[Dict[str, Any]], bool]:
    if limit is None:
        limit = NODE_PROBE_MAX_CANDIDATES
    try:
        cap = int(limit)
    except (TypeError, ValueError):
        cap = NODE_PROBE_MAX_CANDIDATES
    if cap <= 0:
        cap = NODE_PROBE_MAX_CANDIDATES
    if len(nodes) <= cap:
        return nodes, False
    return nodes[:cap], True


def probe_node_tcp(node: Dict[str, Any], timeout: float = NODE_PROBE_TIMEOUT_SEC) -> Tuple[bool, str]:
    """TCP connect probe for a Clash proxy dict. UDP-only types are kept.

    This is file-pool liveness only: no Mihomo delay API, no terminal Clash.
    Private / loopback / link-local / reserved destinations are not contacted
    (same SSRF policy as subscription fetches).
    """
    ntype = str(node.get('type') or '').strip().lower()
    if ntype in UDP_NODE_TYPES:
        return True, 'udp-skip'
    server, port = _node_server_port(node)
    if not server or not port:
        return False, 'missing-server-port'
    allow_private = os.environ.get('ALLOW_PRIVATE_SUBSCRIPTIONS') == '1'
    try:
        pinned = _pin_resolved_ip(server, allow_private=allow_private)
    except ValueError as e:
        err = str(e)[:120]
        if 'Disallowed' in err:
            return False, PROBE_REASON_SSRF
        return False, err
    except OSError as e:
        return False, str(e)[:120]

    try:
        ip_obj = ipaddress.ip_address(pinned)
        if ip_obj.version == 6 and not has_ipv6_route():
            return True, 'ipv6-skip'
    except ValueError:
        pass

    try:
        with socket.create_connection((pinned, port), timeout=timeout):
            return True, 'tcp-ok'
    except OSError as e:
        if getattr(e, 'errno', None) in (errno.ENETUNREACH, 101):
            try:
                if ipaddress.ip_address(pinned).version == 6:
                    return True, 'ipv6-skip'
            except ValueError:
                pass
        return False, str(e)[:120]


def probe_nodes(
    nodes: List[Dict[str, Any]],
    timeout: float = NODE_PROBE_TIMEOUT_SEC,
    max_workers: int = 8,
    keep_ssrf: bool = False,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Split nodes into alive / dead via TCP probe. UDP-only types stay alive.

    ``keep_ssrf=True`` (prune) retains destinations the SSRF filter refused,
    so a LAN node already in the file is not deleted. Inject keeps the default
    and will not add those destinations.
    """
    import concurrent.futures

    alive: List[Dict[str, Any]] = []
    dead: List[Dict[str, Any]] = []
    if not nodes:
        return alive, dead

    def _one(node: Dict[str, Any]) -> Tuple[Dict[str, Any], bool, str]:
        ok, reason = probe_node_tcp(node, timeout=timeout)
        return node, ok, reason

    try:
        worker_cap = int(max_workers)
    except (TypeError, ValueError):
        worker_cap = 8
    workers = max(1, min(worker_cap, NODE_PROBE_MAX_WORKERS, len(nodes)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        for node, ok, reason in pool.map(_one, nodes):
            tagged = dict(node)
            tagged['_probe'] = reason
            if ok:
                alive.append(tagged)
            elif keep_ssrf and reason == PROBE_REASON_SSRF:
                alive.append(tagged)
            else:
                dead.append(tagged)
    return alive, dead


def load_local_nodes_document(path: Path) -> Dict[str, Any]:
    empty = {'proxies': [], 'groups': {}, 'had_groups': False}
    if not path.exists():
        return empty
    try:
        data = fast_yaml_load(path.read_text(encoding='utf-8', errors='ignore')) or {}
    except Exception:
        return empty
    if isinstance(data, list):
        proxies = data
        groups: Dict[str, List[str]] = {}
        had_groups = False
    elif isinstance(data, dict):
        proxies = data.get('proxies') or []
        groups = normalize_simple_groups(data.get('groups'))
        had_groups = 'groups' in data
    else:
        return empty
    nodes = [
        p for p in proxies
        if isinstance(p, dict) and p.get('name') and p.get('type') and p.get('server')
    ]
    kept = {str(p.get('name')) for p in nodes}
    return {
        'proxies': nodes,
        'groups': prune_simple_groups(groups, kept),
        'had_groups': had_groups,
    }


def load_local_nodes_file(path: Path) -> List[Dict[str, Any]]:
    return load_local_nodes_document(path)['proxies']


def load_local_node_groups(path: Path) -> Dict[str, List[str]]:
    return load_local_nodes_document(path)['groups']


def save_local_nodes_file(
    path: Path,
    nodes: List[Dict[str, Any]],
    groups: Optional[Dict[str, List[str]]] = None,
) -> None:
    cleaned: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    for node in nodes:
        if not isinstance(node, dict):
            continue
        item = {k: v for k, v in node.items() if not str(k).startswith('_')}
        name = str(item.get('name') or '').strip()
        if not name or name in seen:
            continue
        if not item.get('type') or not item.get('server'):
            continue
        seen.add(name)
        cleaned.append(item)
    existing = load_local_nodes_document(path)
    if groups is None:
        groups = existing['groups']
    else:
        groups = normalize_simple_groups(groups)
    pruned = prune_simple_groups(groups, seen)
    doc: Dict[str, Any] = {'proxies': cleaned}
    if pruned or existing['had_groups']:
        doc['groups'] = pruned
    path.parent.mkdir(parents=True, exist_ok=True)
    safe_atomic_write(path, fast_yaml_dump(doc))


# ---------------------------------------------------------
# Metadata & Subscription Engine Management
# ---------------------------------------------------------

class SubscriptionEngine:
    """Manages subscriptions, metadata, aggregation, and atomic file operations."""

    def __init__(self, root: Optional[Path] = None):
        self.root, self.meta_file, self.raw_cache_dir, self.merged_output_file, self.lock_file, self.disabled_file = get_paths(root)
        self.local_nodes_file = self.root / 'airports' / 'local-nodes.yaml'
        self.client_export_file = self.root / 'airports' / 'mango-clash.yaml'
        self.client_export_meta_file = self.root / 'airports' / 'mango-clash.meta.json'

    def _get_cache_path(self, sub_id: str) -> Path:
        return self.raw_cache_dir / f"{sub_id}.raw"

    def load_cached_content(self, sub_id: str) -> str:
        cache_p = self._get_cache_path(sub_id)
        if cache_p.exists():
            return cache_p.read_text(encoding='utf-8', errors='ignore')
        return ""

    def save_cached_content(self, sub_id: str, content: str) -> None:
        cache_p = self._get_cache_path(sub_id)
        safe_atomic_write(cache_p, content)

    def load_meta(self) -> Dict[str, Any]:
        if not self.meta_file.exists():
            return {'version': 1, 'subscriptions': []}
        try:
            data = json.loads(self.meta_file.read_text())
            if isinstance(data, dict):
                data.setdefault('version', 1)
                data.setdefault('subscriptions', [])
                return data
        except Exception:
            pass
        return {'version': 1, 'subscriptions': []}

    def save_meta(self, data: Dict[str, Any]) -> None:
        content = json.dumps(data, ensure_ascii=False, indent=2)
        safe_atomic_write(self.meta_file, content)

    def fetch_url(self, url: str, timeout: int = 15) -> str:
        """Fetch subscription content with SSRF protection, no redirects, pinned IP, body cap,
        and fallback to local proxy (e.g. 127.0.0.1:7897) when direct connection fails."""
        safe, err = is_safe_public_url(url)
        if not safe:
            raise ValueError(f"SSRF check failed: {err}")

        user_agent = 'ClashMeta/v1.18.0 mihomo/1.18.0'
        proxy_env = os.environ.get('SUB_FETCH_PROXY', 'http://127.0.0.1:7897').strip()
        proxy_disabled = proxy_env.lower() in ('none', 'off', '0', 'false', '')

        direct_timeout = min(timeout, 8) if not proxy_disabled else timeout
        direct_err: Optional[Exception] = None

        try:
            status, headers, raw, _pinned = _http_get_pinned(
                url,
                timeout=direct_timeout,
                user_agent=user_agent,
            )
            if 300 <= status < 400:
                raise ValueError(
                    f"HTTP {status} redirect refused (subscription fetches do not follow redirects)"
                )
            if status != 200:
                raise ValueError(f"HTTP {status} fetching subscription")
            return raw.decode('utf-8', errors='ignore')
        except Exception as e:
            direct_err = e
            if isinstance(e, ValueError) and 'redirect refused' in str(e):
                raise

        if not proxy_disabled and proxy_env:
            _LOG.info(
                "Subscription direct fetch failed for %s (%s); falling back to proxy %s",
                url,
                direct_err,
                proxy_env,
            )
            try:
                status, headers, raw = _http_get_via_proxy(
                    url,
                    proxy_url=proxy_env,
                    timeout=timeout,
                    user_agent=user_agent,
                )
                if 300 <= status < 400:
                    raise ValueError(
                        f"HTTP {status} redirect refused (subscription fetches do not follow redirects)"
                    )
                if status != 200:
                    raise ValueError(f"HTTP {status} fetching subscription via proxy")
                return raw.decode('utf-8', errors='ignore')
            except Exception as proxy_err:
                raise ValueError(
                    f"Fetch failed (direct: {direct_err}; proxy fallback: {proxy_err})"
                ) from proxy_err

        if direct_err:
            raise direct_err
        raise ValueError("Fetch failed: unknown error")

    def add_subscription(
        self,
        name: str,
        url: Optional[str] = None,
        sub_type: str = 'remote',
        raw_content: Optional[str] = None,
        exclude_filter: Optional[str] = None,
        enabled: bool = True,
        skip_merge: bool = False,
        inject_local: bool = False,
        probe: bool = True,
        target_group: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Add a new subscription source to metadata and process nodes.

        ``skip_merge=True`` keeps the source visible in the panel but out of
        ``airport-merged-sub.yaml`` / live VPS ``config.yaml``.
        ``inject_local=True`` TCP-probes parsed nodes and merges the alive
        ones into ``airports/local-nodes.yaml`` (the client node file).
        URL fetch and TCP probe run outside the subscription lock.
        """
        content = ""
        fetch_error: Optional[str] = None
        if sub_type == 'raw' or raw_content:
            content = raw_content or ''
        elif url:
            try:
                content = self.fetch_url(url)
            except Exception as e:
                fetch_error = f"Fetch failed: {e}"

        pending_inject: Optional[List[Dict[str, Any]]] = None
        with SubscriptionLock(self.lock_file):
            data = self.load_meta()
            subs = data.get('subscriptions', [])

            clean_id = re.sub(r'[^a-zA-Z0-9_\-]', '', name.lower().replace(' ', '-'))
            sub_id = clean_id or f"sub-{len(subs) + 1}"
            suffix = 1
            existing_ids = {s.get('id') for s in subs}
            while sub_id in existing_ids:
                sub_id = f"{clean_id}-{suffix}"
                suffix += 1

            now_iso = datetime.now(timezone.utc).isoformat()
            # target_group only matters when nodes are actually injected into
            # local-nodes.yaml. skip_merge alone (no inject_local) writes nothing,
            # so it must not force membership in the vps-import group.
            if target_group is None and inject_local:
                target_group = 'vps-import'
            effective_filter = (
                exclude_filter.strip()
                if exclude_filter and str(exclude_filter).strip()
                else DEFAULT_EXCLUDE_FILTER
            )
            sub_record: Dict[str, Any] = {
                'id': sub_id,
                'name': name,
                'type': sub_type,  # 'remote' or 'raw'
                'url': url or '',
                'enabled': enabled,
                'exclude_filter': effective_filter,
                'createdAt': now_iso,
                'updatedAt': now_iso,
                'node_count': 0,
                'last_error': fetch_error,
                'skip_merge': bool(skip_merge),
                'target_group': target_group,
            }

            if sub_type == 'raw' or raw_content:
                sub_record['raw_content'] = raw_content or ''
            if content:
                self.save_cached_content(sub_id, content)
                try:
                    nodes = parse_subscription_content(content)
                    filtered = filter_nodes(nodes, sub_record.get('exclude_filter'))
                    sub_record['node_count'] = len(filtered)
                    if inject_local and filtered:
                        pending_inject = apply_node_name_prefix(filtered, name)
                except Exception as e:
                    sub_record['last_error'] = f"Parse failed: {e}"

            subs.append(sub_record)
            data['subscriptions'] = subs
            self.save_meta(data)
            self.reconcile_merged()

        inject_result: Optional[Dict[str, Any]] = None
        if pending_inject:
            inject_result = self._inject_alive_into_local_nodes(
                pending_inject,
                probe=probe,
                target_group=target_group,
            )
            with SubscriptionLock(self.lock_file):
                data = self.load_meta()
                for sub in data.get('subscriptions', []):
                    if sub.get('id') == sub_id:
                        sub['injected_alive'] = inject_result.get('injected', 0)
                        sub['injected_dead'] = inject_result.get('dead', 0)
                        sub_record = sub
                        break
                self.save_meta(data)

        if fetch_error:
            return {
                'success': False,
                'error': fetch_error,
                'subscription': sub_record,
            }

        result: Dict[str, Any] = {'success': True, 'subscription': sub_record}
        if inject_result is not None:
            result['inject'] = inject_result
        return result

    def update_subscription(
        self,
        sub_id: str,
        name: Optional[str] = None,
        url: Optional[str] = None,
        raw_content: Optional[str] = None,
        exclude_filter: Optional[str] = None,
        enabled: Optional[bool] = None,
        refresh: bool = False,
        inject_local: Optional[bool] = None,
        probe: bool = True,
        target_group: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Update subscription metadata and optionally re-fetch/parse.

        URL fetch and TCP probe run outside the subscription lock. A skip_merge
        (or explicit inject_local) refresh re-injects alive nodes into
        ``airports/local-nodes.yaml``. Fetch failure is ``success: False``.
        """
        fetch_url_value: Optional[str] = None
        with SubscriptionLock(self.lock_file):
            data = self.load_meta()
            subs = data.get('subscriptions', [])
            sub = next((s for s in subs if s.get('id') == sub_id), None)
            if not sub:
                return {'success': False, 'error': f"Subscription '{sub_id}' not found"}

            old_sub_name = sub.get('name')
            if name is not None:
                sub['name'] = name
            if url is not None:
                sub['url'] = url
            if raw_content is not None:
                sub['raw_content'] = raw_content
                self.save_cached_content(sub_id, raw_content)
            if exclude_filter is not None:
                sub['exclude_filter'] = (
                    exclude_filter.strip()
                    if str(exclude_filter).strip()
                    else DEFAULT_EXCLUDE_FILTER
                )
            if target_group is not None:
                sub['target_group'] = target_group.strip() if str(target_group).strip() else None
            if enabled is not None:
                sub['enabled'] = enabled

            # A rename changes the injected name prefix; retract the old names
            # so they do not survive in local-nodes.yaml as orphans.
            if old_sub_name and sub.get('name') != old_sub_name:
                self._retract_prefixed_nodes(old_sub_name)

            sub['updatedAt'] = datetime.now(timezone.utc).isoformat()
            self.save_meta(data)
            if not refresh:
                self.reconcile_merged()
                return {'success': True, 'subscription': sub}

            if not (sub.get('type') == 'raw' or sub.get('raw_content')) and sub.get('url'):
                fetch_url_value = sub.get('url')

        content = ""
        fetch_error: Optional[str] = None
        if refresh:
            if sub.get('type') == 'raw' or sub.get('raw_content'):
                content = sub.get('raw_content', '') or ''
            elif fetch_url_value:
                try:
                    content = self.fetch_url(fetch_url_value)
                except Exception as e:
                    fetch_error = f"Fetch failed: {e}"

        pending_inject: Optional[List[Dict[str, Any]]] = None
        with SubscriptionLock(self.lock_file):
            data = self.load_meta()
            sub = next((s for s in data.get('subscriptions', []) if s.get('id') == sub_id), None)
            if not sub:
                return {'success': False, 'error': f"Subscription '{sub_id}' not found"}

            if refresh:
                sub['last_error'] = fetch_error
                if content:
                    self.save_cached_content(sub_id, content)
                    try:
                        nodes = parse_subscription_content(content)
                        filtered = filter_nodes(nodes, sub.get('exclude_filter'))
                        sub['node_count'] = len(filtered)
                        want_inject = (
                            bool(inject_local)
                            if inject_local is not None
                            else bool(sub.get('skip_merge'))
                        )
                        if want_inject and filtered:
                            pending_inject = apply_node_name_prefix(
                                filtered, sub.get('name', sub_id)
                            )
                    except Exception as e:
                        sub['last_error'] = f"Parse failed: {e}"
                elif fetch_error is None and not (sub.get('type') == 'raw' or sub.get('raw_content')):
                    if not sub.get('url'):
                        sub['last_error'] = 'Fetch failed: missing URL'

            sub['updatedAt'] = datetime.now(timezone.utc).isoformat()
            self.save_meta(data)
            self.reconcile_merged()

        inject_result: Optional[Dict[str, Any]] = None
        if pending_inject:
            # Legacy records predate target_group; a refresh that injects nodes
            # must still land them in the whitelist group or they are dropped
            # by apply-local-import's groups.vps-import contract.
            target_group = (sub.get('target_group') if isinstance(sub, dict) else None) or 'vps-import'
            inject_result = self._inject_alive_into_local_nodes(
                pending_inject,
                probe=probe,
                target_group=target_group,
            )
            with SubscriptionLock(self.lock_file):
                data = self.load_meta()
                for item in data.get('subscriptions', []):
                    if item.get('id') == sub_id:
                        item['injected_alive'] = inject_result.get('injected', 0)
                        item['injected_dead'] = inject_result.get('dead', 0)
                        sub = item
                        break
                self.save_meta(data)

        if fetch_error:
            result: Dict[str, Any] = {
                'success': False,
                'error': fetch_error,
                'subscription': sub,
            }
            if inject_result is not None:
                result['inject'] = inject_result
            return result

        result = {'success': True, 'subscription': sub}
        if inject_result is not None:
            result['inject'] = inject_result
        return result

    def _retract_prefixed_nodes(self, sub_name: Optional[str]) -> int:
        """Drop ``[<sub_name>] ``-prefixed nodes from local-nodes.yaml and all groups.

        Injected node names are namespaced by subscription name, so a deleted or
        renamed source can have its names retracted without touching other
        sources. Returns the number of proxies removed.
        """
        if not sub_name:
            return 0
        prefix = f"[{sub_name}] "
        try:
            doc = load_local_nodes_document(self.local_nodes_file)
            kept = [p for p in doc['proxies'] if not str(p.get('name') or '').startswith(prefix)]
            removed = len(doc['proxies']) - len(kept)
            if not removed:
                return 0
            groups = {
                gname: [n for n in names if not str(n).startswith(prefix)]
                for gname, names in doc['groups'].items()
            }
            save_local_nodes_file(self.local_nodes_file, kept, groups=groups)
            return removed
        except Exception:
            # A malformed local-nodes.yaml must not block metadata changes.
            return 0

    def delete_subscription(self, sub_id: str) -> Dict[str, Any]:
        """Delete a subscription by id and retract its injected nodes.

        Node names are namespaced by ``[<subscription name>] ``; removing the
        subscription also retracts those names from ``airports/local-nodes.yaml``
        (proxies and every group) so they stop flowing into the live VPS
        ``config.yaml`` on the next apply. Existing denylist entries are left
        untouched.
        """
        with SubscriptionLock(self.lock_file):
            data = self.load_meta()
            subs = data.get('subscriptions', [])
            idx = next((i for i, s in enumerate(subs) if s.get('id') == sub_id), -1)
            if idx < 0:
                return {'success': False, 'error': f"Subscription '{sub_id}' not found"}

            deleted = subs.pop(idx)
            cache_p = self._get_cache_path(sub_id)
            if cache_p.exists():
                try:
                    cache_p.unlink()
                except Exception:
                    pass

            retracted = self._retract_prefixed_nodes(deleted.get('name'))

            data['subscriptions'] = subs
            self.save_meta(data)
            self.reconcile_merged()
            return {'success': True, 'deleted': deleted, 'retracted': retracted}

    def prune_dead_nodes(
        self,
        batch_size: int = 15,
        max_workers: int = 5,
        timeout_ms: int = 5000,
        batch_pause_sec: float = 0.3,
        max_candidates: int = 30,
        test_url: str = "http://www.gstatic.com/generate_204",
        controller_api: str = "http://127.0.0.1:9090",
        controller_secret: Optional[str] = None,
        whitelist_prefixes: Tuple[str, ...] = ("GVPS-", "Aliyun-", "DIRECT", "REJECT"),
        apply_filter: bool = True,
        max_retries: int = 2,
    ) -> Dict[str, Any]:
        """Perform throttled, chunked health-check across active nodes and filter dead nodes into denylist.
        
        Key design requirements:
          - Never test too many nodes at once (strict chunking with pause between batches).
          - Low concurrency (default 5 workers) to avoid starving Mihomo controller or socket limits.
          - Never disable whitelisted critical infrastructure nodes (e.g. GVPS-*, Aliyun-*).
          - Atomic updates to disabled-nodes.txt and atomic reconciliation into config files.
        """
        import concurrent.futures
        import time

        secret = controller_secret
        if secret is None:
            secret_file = self.root / ".controller-secret"
            if secret_file.exists():
                try:
                    secret = secret_file.read_text(encoding="utf-8").strip()
                except Exception:
                    secret = ""

        headers = {}
        if secret:
            headers["Authorization"] = f"Bearer {secret}"

        # 1. Fetch current proxy list from Mihomo controller
        req = urllib.request.Request(f"{controller_api}/proxies", headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                proxies_resp = json.loads(resp.read().decode("utf-8", errors="ignore"))
                proxies_map = proxies_resp.get("proxies", {})
        except Exception as e:
            return {"success": False, "error": f"Failed to fetch proxies from Mihomo: {e}"}

        # 2. Extract leaf proxies (exclude proxy groups and built-in specials)
        group_types = {
            "Selector", "URLTest", "Fallback", "LoadBalance", "Relay",
            "Direct", "Reject", "Compatible", "Pass", "PassRule", "RejectDrop"
        }
        leaf_names: List[str] = []
        for name, p in proxies_map.items():
            if not isinstance(p, dict):
                continue
            if p.get("type") in group_types:
                continue
            if name in ("DIRECT", "REJECT", "GLOBAL"):
                continue
            # Skip whitelisted prefixes
            if any(name.startswith(pfx) for pfx in whitelist_prefixes):
                continue
            leaf_names.append(name)

        # Exclude already disabled nodes from testing
        existing_disabled = load_disabled_nodes(self.disabled_file)
        to_test = [n for n in leaf_names if n not in existing_disabled]

        # Safety: default cap to max 30 candidates per invocation to prevent long-running blocking requests
        if max_candidates and len(to_test) > max_candidates:
            to_test = to_test[:max_candidates]

        total_to_test = len(to_test)
        tested_count = 0
        alive_nodes: List[Dict[str, Any]] = []
        newly_dead: List[str] = []

        def probe_node(name: str) -> Tuple[str, Optional[int]]:
            q_name = urllib.parse.quote(name, safe="")
            q_url = urllib.parse.quote(test_url, safe="")
            delay_url = f"{controller_api}/proxies/{q_name}/delay?timeout={timeout_ms}&url={q_url}"
            attempts = max(1, max_retries)
            for attempt in range(attempts):
                try:
                    preq = urllib.request.Request(delay_url, headers=headers)
                    with urllib.request.urlopen(preq, timeout=(timeout_ms / 1000.0) + 2.0) as presp:
                        res_data = json.loads(presp.read().decode("utf-8", errors="ignore"))
                        delay = res_data.get("delay")
                        if delay is not None and isinstance(delay, (int, float)):
                            return name, int(delay)
                except Exception:
                    pass
                if attempt + 1 < attempts:
                    time.sleep(0.5)
            return name, None

        # 3. Process in chunks to prevent CPU / socket spikes
        for i in range(0, total_to_test, batch_size):
            chunk = to_test[i:i + batch_size]
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                results = list(executor.map(probe_node, chunk))

            for name, delay in results:
                tested_count += 1
                if delay is not None:
                    alive_nodes.append({"name": name, "delay": delay})
                else:
                    newly_dead.append(name)

            if i + batch_size < total_to_test and batch_pause_sec > 0:
                time.sleep(batch_pause_sec)

        # 4. Apply filter if requested
        targets_updated = []
        if apply_filter and newly_dead:
            with SubscriptionLock(self.lock_file):
                save_disabled_nodes(set(newly_dead), self.disabled_file)
                all_disabled = load_disabled_nodes(self.disabled_file)

                # Reconcile target configs (config.yaml, config.mac-merged.yaml)
                for target in (self.root / 'config.mac-merged.yaml', self.root / 'config.yaml'):
                    if target.exists():
                        if reconcile_target_config(target, None, disabled_nodes=all_disabled):
                            targets_updated.append(str(target))

        return {
            "success": True,
            "total_candidates": total_to_test,
            "tested_count": tested_count,
            "alive_count": len(alive_nodes),
            "dead_count": len(newly_dead),
            "newly_dead": newly_dead,
            "alive": alive_nodes[:20],  # Sample of alive nodes
            "applied_filter": apply_filter,
            "targets_updated": targets_updated,
        }

    def list_subscriptions(self) -> List[Dict[str, Any]]:
        """List all subscriptions."""
        data = self.load_meta()
        return data.get('subscriptions', [])

    def import_raw_nodes(
        self,
        name: str,
        raw_text: str,
        exclude_filter: Optional[str] = None,
        skip_merge: bool = False,
        inject_local: bool = False,
        probe: bool = True,
        target_group: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Import nodes from raw text (URIs or Base64).

        Panel HTTP import passes ``skip_merge=True`` so a paste cannot rewrite
        live VPS ``config.yaml``. CLI/tests keep the historical mergeable default.
        """
        return self.add_subscription(
            name=name,
            sub_type='raw',
            raw_content=raw_text,
            exclude_filter=exclude_filter,
            enabled=True,
            skip_merge=skip_merge,
            inject_local=inject_local,
            probe=probe,
            target_group=target_group,
        )

    def _inject_alive_into_local_nodes(
        self,
        nodes: List[Dict[str, Any]],
        probe: bool = True,
        target_group: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Merge alive nodes into airports/local-nodes.yaml.

        Probe I/O is outside the lock. A failed first-time TCP probe is skipped
        and is **not** written to ``disabled-nodes.txt`` (transient network
        must not permanently blacklist a brand-new name). Already-denylisted
        names stay out.
        """
        with SubscriptionLock(self.lock_file):
            disabled = load_disabled_nodes(self.disabled_file)
            candidates = [
                n for n in nodes
                if isinstance(n, dict) and str(n.get('name') or '').strip() not in disabled
            ]

        truncated = False
        if probe:
            candidates, truncated = _cap_probe_candidates(candidates)
            alive, dead = probe_nodes(candidates)
        else:
            alive, dead = candidates, []

        with SubscriptionLock(self.lock_file):
            disabled = load_disabled_nodes(self.disabled_file)
            existing_doc = load_local_nodes_document(self.local_nodes_file)
            existing = existing_doc['proxies']
            groups = dict(existing_doc['groups'])
            by_name = {str(n.get('name')): n for n in existing}
            injected = 0
            new_alive_names: List[str] = []
            for node in alive:
                name = str(node.get('name') or '').strip()
                if not name or name in disabled:
                    continue
                if name not in by_name:
                    injected += 1
                by_name[name] = node
                # Only include nodes that are routable/usable for target_group
                # For example, if host has no IPv6, do not put ipv6-skip nodes into vps-import
                if target_group == 'vps-import' and node.get('_probe') == 'ipv6-skip':
                    continue
                new_alive_names.append(name)

            if target_group and new_alive_names:
                grp_list = list(groups.get(target_group, []))
                for nname in new_alive_names:
                    if nname not in grp_list:
                        grp_list.append(nname)
                groups[target_group] = grp_list

            save_local_nodes_file(self.local_nodes_file, list(by_name.values()), groups=groups)

        dead_names = [str(n.get('name') or '').strip() for n in dead if n.get('name')]
        return {
            'probed': len(candidates),
            'injected': injected,
            'alive': len(alive),
            'dead': len(dead_names),
            'dead_names': dead_names,
            'local_count': len(by_name),
            'truncated': truncated,
            'max_candidates': NODE_PROBE_MAX_CANDIDATES,
        }

    def prune_local_node_file(
        self,
        timeout: float = NODE_PROBE_TIMEOUT_SEC,
        max_workers: int = 8,
        apply_filter: bool = True,
    ) -> Dict[str, Any]:
        """TCP-probe airports/local-nodes.yaml and drop dead names into the denylist.

        Does not rewrite VPS ``config.yaml`` and does not talk to a terminal Clash.
        UDP-only node types are kept. Probe I/O is outside the lock. Destinations
        refused by the SSRF filter stay in the file (not treated as dead).
        """
        with SubscriptionLock(self.lock_file):
            existing = load_local_nodes_file(self.local_nodes_file)
            already = load_disabled_nodes(self.disabled_file)
            to_test = [n for n in existing if str(n.get('name') or '').strip() not in already]

        to_test, truncated = _cap_probe_candidates(to_test)
        alive, dead = probe_nodes(
            to_test,
            timeout=timeout,
            max_workers=max_workers,
            keep_ssrf=True,
        )
        dead_keys = {_node_endpoint_key(n) for n in dead if str(n.get('name') or '').strip()}
        newly_dead = [key[0] for key in dead_keys if key[0]]
        skipped_replaced = 0
        if apply_filter:
            with SubscriptionLock(self.lock_file):
                already = load_disabled_nodes(self.disabled_file)
                current = load_local_nodes_file(self.local_nodes_file)
                kept: List[Dict[str, Any]] = []
                drop_names: List[str] = []
                dropped_keys: Set[Tuple[str, str, Optional[int]]] = set()
                for n in current:
                    name = str(n.get('name') or '').strip()
                    if name in already:
                        continue
                    key = _node_endpoint_key(n)
                    if key in dead_keys:
                        drop_names.append(name)
                        dropped_keys.add(key)
                        continue
                    kept.append(n)
                skipped_replaced = len(dead_keys - dropped_keys)
                if drop_names:
                    save_disabled_nodes(set(drop_names), self.disabled_file)
                    newly_dead = drop_names
                else:
                    newly_dead = []
                save_local_nodes_file(self.local_nodes_file, kept)
        else:
            kept = [
                n for n in existing
                if str(n.get('name') or '').strip() not in already
                and _node_endpoint_key(n) not in dead_keys
            ]

        return {
            'success': True,
            'total_candidates': len(to_test),
            'tested_count': len(to_test),
            'alive_count': len(alive),
            'dead_count': len(newly_dead),
            'newly_dead': newly_dead,
            'alive': [{'name': str(n.get('name')), 'delay': None} for n in alive[:20]],
            'applied_filter': apply_filter,
            'targets_updated': [str(self.local_nodes_file)] if apply_filter else [],
            'local_count': len(kept) if apply_filter else len(existing),
            'truncated': truncated,
            'max_candidates': NODE_PROBE_MAX_CANDIDATES,
            'skipped_replaced': skipped_replaced if apply_filter else 0,
        }

    def reconcile_merged(self, fetch_remote: bool = False, update_targets: bool = True) -> Dict[str, Any]:
        """Aggregate all enabled subscriptions and write airports/airport-merged-sub.yaml.

        ``update_targets=False`` writes the merged airport file only. Client
        export must use that mode so an empty panel subscription list cannot
        wipe ``🌐 订阅导入`` out of the live VPS ``config.yaml``.
        """
        data = self.load_meta()
        subs = data.get('subscriptions', [])

        all_proxies: List[Dict[str, Any]] = []
        seen_names: set[str] = set()

        for sub in subs:
            if not sub.get('enabled', True):
                continue
            # Panel-visible local inventory (airports/local-nodes.yaml) must not
            # be prefix-merged into VPS config.yaml / airport-merged-sub.yaml.
            if sub.get('skip_merge'):
                continue

            sub_id = sub.get('id', '')
            content = ""

            # Check cache or memory
            if not fetch_remote:
                content = self.load_cached_content(sub_id) or sub.get('raw_content', '')

            # If fetch_remote or cache missing, fetch
            if not content:
                if sub.get('type') == 'raw' or sub.get('raw_content'):
                    content = sub.get('raw_content', '')
                    if content:
                        self.save_cached_content(sub_id, content)
                elif sub.get('url'):
                    try:
                        content = self.fetch_url(sub['url'])
                        self.save_cached_content(sub_id, content)
                    except Exception as e:
                        sub['last_error'] = str(e)
                        continue

            if not content:
                continue

            try:
                nodes = parse_subscription_content(content)
                filtered = filter_nodes(nodes, sub.get('exclude_filter'))
                sub['node_count'] = len(filtered)
                renamed = apply_node_name_prefix(filtered, sub.get('name', sub_id))

                for node in renamed:
                    n_name = node['name']
                    final_name = n_name
                    dup_idx = 1
                    while final_name in seen_names:
                        final_name = f"{n_name} ({dup_idx})"
                        dup_idx += 1
                    node['name'] = final_name
                    seen_names.add(final_name)
                    all_proxies.append(node)
            except Exception as e:
                sub['last_error'] = str(e)

        # Output YAML
        merged_doc = {
            'proxies': all_proxies,
        }

        rendered = fast_yaml_dump(merged_doc)
        safe_atomic_write(self.merged_output_file, rendered)

        targets_updated = []
        mergeable_subs = [
            s for s in subs
            if s.get('enabled', True) and not s.get('skip_merge')
        ]
        # An empty panel must never wipe live VPS groups (keeper / airport
        # files still own config.yaml). Only rewrite targets when there is at
        # least one mergeable subscription.
        if update_targets and not mergeable_subs:
            update_targets = False
        if update_targets:
            disabled_set = load_disabled_nodes(self.disabled_file)
            for target in (self.root / 'config.mac-merged.yaml', self.root / 'config.yaml'):
                if target.exists():
                    if reconcile_target_config(target, all_proxies, disabled_nodes=disabled_set):
                        targets_updated.append(str(target))

        return {
            'success': True,
            'proxy_count': len(all_proxies),
            'output_file': str(self.merged_output_file),
            'targets_updated': targets_updated,
        }

    def get_or_create_client_token(self) -> str:
        """Return the Clash client-export token, creating one if missing.

        Env ``CLIENT_SUB_TOKEN`` always wins so production can pin a secret
        without rewriting the token file.
        """
        env_token = (os.environ.get('CLIENT_SUB_TOKEN') or '').strip()
        if env_token:
            return env_token
        path = self.root / 'subscriptions/client-export.token'
        if path.exists():
            existing = path.read_text(encoding='utf-8', errors='ignore').strip()
            if existing:
                try:
                    os.chmod(path, CLIENT_EXPORT_TOKEN_MODE)
                except OSError:
                    pass
                return existing
        token = secrets.token_urlsafe(24)
        path.parent.mkdir(parents=True, exist_ok=True)
        safe_atomic_write(path, token + '\n', mode=CLIENT_EXPORT_TOKEN_MODE)
        return token

    def _load_local_nodes(self) -> List[Dict[str, Any]]:
        return load_local_nodes_file(self.local_nodes_file)

    def render_client_clash_config(self, fetch_remote: bool = False) -> str:
        """Render a complete Clash Meta client YAML for Mac/Windows Verge.

        Combines enabled subscription proxies + optional ``airports/local-nodes.yaml``,
        strips the denylist, and injects DNS bootstrap + DIRECT rules that keep
        TUN + fake-ip from hijacking LAN / Cloudflare Tunnel / self-hosted inbounds.
        Never rewrites VPS ``config.yaml`` (``update_targets=False``).
        """
        self.reconcile_merged(fetch_remote=fetch_remote, update_targets=False)
        disabled = load_disabled_nodes(self.disabled_file)

        proxies: List[Dict[str, Any]] = []
        seen: Set[str] = set()

        merged_path = self.merged_output_file
        if merged_path.exists():
            try:
                merged = fast_yaml_load(merged_path.read_text(encoding='utf-8', errors='ignore')) or {}
                for node in (merged.get('proxies') or []) if isinstance(merged, dict) else []:
                    if not isinstance(node, dict):
                        continue
                    name = str(node.get('name') or '').strip()
                    if not name or name in disabled or name in seen:
                        continue
                    seen.add(name)
                    proxies.append(node)
            except Exception:
                pass

        for node in self._load_local_nodes():
            name = str(node.get('name') or '').strip()
            if not name or name in disabled or name in seen:
                continue
            seen.add(name)
            proxies.append(node)

        proxies = drop_unresolved_dialer_proxies(proxies)
        names = [str(p['name']) for p in proxies]
        available = set(names)
        auto_members = names or ['DIRECT']
        select_members = ['AUTO'] + names + ['DIRECT']
        simple_groups = load_local_node_groups(self.local_nodes_file)
        google_fallback = [n for n in names if _is_us_google_node(n)]
        google_members = resolve_simple_group(
            simple_groups,
            LOCAL_GROUP_GOOGLE,
            available,
            fallback=google_fallback,
        ) or ['PROXY']

        doc: Dict[str, Any] = {
            'mixed-port': 7897,
            'allow-lan': client_allow_lan(),
            'mode': 'rule',
            'log-level': 'info',
            'ipv6': True,
            'unified-delay': True,
            'tun': dict(CLIENT_TUN),
            'dns': dict(CLIENT_DNS),
            'proxies': proxies,
            'proxy-groups': [
                dict(CLIENT_MANGO_CF_GROUP),
                {
                    'name': 'PROXY',
                    'type': 'select',
                    'proxies': select_members,
                },
                {
                    'name': 'AUTO',
                    'type': 'url-test',
                    'url': 'http://www.gstatic.com/generate_204',
                    'interval': 300,
                    'tolerance': 50,
                    'proxies': auto_members,
                },
                {
                    'name': GOOGLE_GROUP,
                    'type': 'select',
                    'proxies': google_members,
                },
            ],
            'rules': (
                list(CLIENT_MANGO_CF_RULES)
                + list(CLIENT_DOMESTIC_MEDIA_RULES)
                + list(CLIENT_STUN_RULES)
                + list(CLIENT_DIRECT_RULES)
                + list(CLIENT_GOOGLE_RULES)
                + list(CLIENT_FINAL_RULES)
            ),
        }
        return fast_yaml_dump(doc)

    def load_last_good_client_yaml(self) -> Optional[str]:
        path = self.client_export_file
        if not path.exists():
            return None
        try:
            text = path.read_text(encoding='utf-8')
        except OSError:
            return None
        if not text.strip():
            return None
        return text

    def _usable_last_good(self) -> Optional[Tuple[str, str]]:
        """Return (yaml, sha256) only if last-good still passes structure checks."""
        last_good = self.load_last_good_client_yaml()
        if last_good is None:
            return None
        errors = validate_client_clash_yaml(last_good)
        if errors:
            _export_warn('mango-clash last-good invalid: %s' % '; '.join(errors[:8]))
            return None
        return last_good, sha256_text(last_good)

    def _serve_last_good(
        self,
        last: Tuple[str, str],
        errors: List[str],
    ) -> Dict[str, Any]:
        yaml_text, digest = last
        _export_warn('mango-clash publish rejected; serving last-good: %s' % '; '.join(errors[:8]))
        return {
            'ok': True,
            'published': False,
            'served_last_good': True,
            'yaml': yaml_text,
            'sha256': digest,
            'errors': errors,
        }

    def _client_export_inputs_fingerprint(self) -> str:
        parts = [
            CLIENT_EXPORT_RENDER_REV,
            'allow-lan=' + ('1' if client_allow_lan() else '0'),
            'local=' + sha256_file(self.local_nodes_file),
            'merged=' + sha256_file(self.merged_output_file),
            'disabled=' + sha256_file(self.disabled_file),
        ]
        return sha256_text('\n'.join(parts))

    def _load_client_export_meta(self) -> Dict[str, Any]:
        path = self.client_export_meta_file
        if not path.exists():
            return {}
        try:
            data = json.loads(path.read_text(encoding='utf-8'))
        except Exception:
            return {}
        return data if isinstance(data, dict) else {}

    def publish_client_clash_config(self, fetch_remote: bool = False) -> Dict[str, Any]:
        """Validate a fresh render; only then replace last-good bytes.

        Illegal YAML never changes the served version. Clash Verge treats a
        remote profile version as the content hash, so keeping last-good
        (plus a stable ETag) is what stops a broken render from being adopted.
        Last-good is re-validated before being served so a corrupt file cannot
        become the client version.
        """
        last = self._usable_last_good()
        kernel_bin = self.root / 'mihomo'
        if last is not None and not fetch_remote:
            meta = self._load_client_export_meta()
            if (
                meta.get('inputs') == self._client_export_inputs_fingerprint()
                and meta.get('sha256') == last[1]
            ):
                return {
                    'ok': True,
                    'published': False,
                    'served_last_good': False,
                    'yaml': last[0],
                    'sha256': last[1],
                    'errors': [],
                }
        try:
            candidate = self.render_client_clash_config(fetch_remote=fetch_remote)
        except Exception as e:
            errors = [f'render: {e}']
            if last is not None:
                return self._serve_last_good(last, errors)
            raise ClientExportInvalid(errors) from e

        digest = sha256_text(candidate)
        inputs = self._client_export_inputs_fingerprint()
        if last is not None and digest == last[1]:
            meta = {
                'sha256': digest,
                'inputs': inputs,
                'updatedAt': datetime.now(timezone.utc).isoformat(),
                'bytes': len(candidate.encode('utf-8')),
            }
            safe_atomic_write(self.client_export_meta_file, json.dumps(meta, ensure_ascii=False, indent=2) + '\n')
            return {
                'ok': True,
                'published': False,
                'served_last_good': False,
                'yaml': last[0],
                'sha256': digest,
                'errors': [],
            }

        errors = validate_client_clash_yaml(
            candidate,
            kernel_bin=kernel_bin,
            workdir=self.root,
        )
        if errors:
            if last is not None:
                return self._serve_last_good(last, errors)
            raise ClientExportInvalid(errors)

        safe_atomic_write(self.client_export_file, candidate)
        meta = {
            'sha256': digest,
            'inputs': inputs,
            'updatedAt': datetime.now(timezone.utc).isoformat(),
            'bytes': len(candidate.encode('utf-8')),
        }
        safe_atomic_write(self.client_export_meta_file, json.dumps(meta, ensure_ascii=False, indent=2) + '\n')
        return {
            'ok': True,
            'published': True,
            'served_last_good': False,
            'yaml': candidate,
            'sha256': digest,
            'errors': [],
        }


# ---------------------------------------------------------
# CLI Interface
# ---------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description='Clash Subscription Manager')
    parser.add_argument('--list', action='store_true', help='List all subscriptions')
    parser.add_argument('--add', nargs=2, metavar=('NAME', 'URL'), help='Add a remote subscription')
    parser.add_argument('--update', metavar='ID', help='Update/refresh a subscription by ID')
    parser.add_argument('--delete', metavar='ID', help='Delete a subscription by ID')
    parser.add_argument('--import-nodes', nargs=2, metavar=('NAME', 'TEXT'), help='Import nodes from raw text')
    parser.add_argument('--target-group', metavar='GROUP', help='Target simple group in local-nodes.yaml (e.g. vps-import)')
    parser.add_argument('--skip-merge', action='store_true', help='Set skip_merge=True to isolate nodes from VPS merged config')
    parser.add_argument('--reconcile', action='store_true', help='Reconcile and regenerate merged airport config')
    parser.add_argument('--fetch', action='store_true', help='Force re-fetching remote subscriptions during reconcile')
    parser.add_argument('--prune-dead', action='store_true', help='Mihomo :9090 delay prune (VPS controller). Panel toolkit uses prune_local_node_file instead.')
    parser.add_argument('--export-client', action='store_true', help='Print a complete Clash Meta client YAML to stdout')
    parser.add_argument('--batch-size', type=int, default=15, help='Batch size for health checks (default: 15)')
    parser.add_argument('--max-workers', type=int, default=5, help='Max concurrent workers for health checks (default: 5)')
    parser.add_argument('--dry-run', action='store_true', help='Perform health checks without applying filter to configs')
    args = parser.parse_args()

    engine = SubscriptionEngine()

    if args.prune_dead:
        res = engine.prune_dead_nodes(
            batch_size=args.batch_size,
            max_workers=args.max_workers,
            apply_filter=not args.dry_run,
        )
        print(json.dumps(res, ensure_ascii=False, indent=2))
        sys.exit(0 if res.get('success') else 1)

    if args.list:
        subs = engine.list_subscriptions()
        print(json.dumps(subs, ensure_ascii=False, indent=2))
        sys.exit(0)

    if args.add:
        name, url = args.add
        res = engine.add_subscription(
            name=name,
            url=url,
            skip_merge=args.skip_merge,
            target_group=args.target_group,
            inject_local=bool(args.target_group or args.skip_merge),
        )
        print(json.dumps(res, ensure_ascii=False, indent=2))
        sys.exit(0 if res.get('success') else 1)

    if args.update:
        res = engine.update_subscription(sub_id=args.update, refresh=True)
        print(json.dumps(res, ensure_ascii=False, indent=2))
        sys.exit(0 if res.get('success') else 1)

    if args.delete:
        res = engine.delete_subscription(sub_id=args.delete)
        print(json.dumps(res, ensure_ascii=False, indent=2))
        sys.exit(0 if res.get('success') else 1)

    if args.import_nodes:
        name, text = args.import_nodes
        res = engine.import_raw_nodes(
            name=name,
            raw_text=text,
            skip_merge=args.skip_merge,
            target_group=args.target_group,
            inject_local=bool(args.target_group or args.skip_merge),
        )
        print(json.dumps(res, ensure_ascii=False, indent=2))
        sys.exit(0 if res.get('success') else 1)

    if args.reconcile:
        res = engine.reconcile_merged(fetch_remote=args.fetch)
        print(json.dumps(res, ensure_ascii=False, indent=2))
        sys.exit(0 if res.get('success') else 1)

    if args.export_client:
        published = engine.publish_client_clash_config(fetch_remote=args.fetch)
        print(published['yaml'], end='')
        sys.exit(0)

    parser.print_help()


if __name__ == '__main__':
    main()
