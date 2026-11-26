#!/usr/bin/env python3
"""Cluster-wide Mihomo live configuration reloader for tebi and pxed.

Coordinates zero-downtime hot reload (PUT /configs?force=true) across both
cluster nodes. The local node is reloaded directly via 127.0.0.1:9090, while
the remote peer node is reloaded via its zashboard-gateway reverse proxy
(port 2053) across the VPC.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import socket
import sys
import urllib.request
from pathlib import Path
from typing import Any, Dict, Optional

_LOG = logging.getLogger('clash.cluster_reload')

CLASH_ROOT_ENV = os.environ.get('CLASH_ROOT')
ROOT = Path(CLASH_ROOT_ENV).resolve() if CLASH_ROOT_ENV else Path('/personal/clash')
PERSONAL_ROOT_ENV = os.environ.get('PERSONAL_ROOT')
PERSONAL_ROOT = Path(PERSONAL_ROOT_ENV).resolve() if PERSONAL_ROOT_ENV else Path('/personal')
PANEL_PASSWORD_FILE_ENV = os.environ.get('PANEL_PASSWORD_FILE')
PANEL_PASSWORD_FILE = (
    Path(PANEL_PASSWORD_FILE_ENV).resolve()
    if PANEL_PASSWORD_FILE_ENV
    else Path('/personal/zashboard/panel.password')
)
CONTROLLER_SECRET_FILE = ROOT / '.controller-secret'


def is_pxed_host() -> bool:
    """True if running on pxed host, false if tebi or unknown."""
    if os.environ.get('NODE_NAME') == 'pxed':
        return True
    if os.environ.get('NODE_NAME') == 'tebi':
        return False
    return os.path.exists('/data/tuntunshu') or 'pxed' in socket.gethostname().lower()


def get_remote_node_ip(target_node: str, personal_dir: Optional[Path] = None) -> str:
    """Resolve internal IP for peer node.

    2026-11-25 去 Bohrium 内网 IP 依赖（pxed 容器半死事故沉淀）：mesh 地址
    （EasyTier 10.144.144.x）优先——跨容器稳定、不随 Bohrium 调度变化；
    10.5.103.x Bohrium 内网 IP 降级为兜底（mesh 断时容器间仍可能内网互通）。
    """
    base = personal_dir or PERSONAL_ROOT
    ip_file = base / target_node / 'internal-ip'
    if ip_file.exists():
        try:
            ip = ip_file.read_text().strip()
            if ip:
                return ip
        except Exception:
            pass
    if target_node == 'pxed':
        # 2026-11-26 pxed 报废销毁：peer 不复存在，返回 0.0.0.0 快速失败
        # （原 10.144.144.31 / 10.5.103.87 均已死，勿再回填）。
        return '0.0.0.0'
    if target_node == 'tebi':
        return '10.144.144.32' if _mesh_reachable('10.144.144.32') else '10.5.103.26'
    return '127.0.0.1'


def _mesh_reachable(ip: str, port: int = 2053, timeout: float = 1.5) -> bool:
    """Probe mesh IP TCP reachability (gateway port) before preferring it."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def get_controller_secret() -> str:
    if CONTROLLER_SECRET_FILE.exists():
        try:
            return CONTROLLER_SECRET_FILE.read_text().strip()
        except Exception:
            pass
    return ''


def get_panel_password() -> str:
    if PANEL_PASSWORD_FILE.exists():
        try:
            return PANEL_PASSWORD_FILE.read_text().strip()
        except Exception:
            pass
    return ''


def reload_local(
    config_path: Optional[Path] = None,
    timeout: float = 10.0,
    port: int = 9090,
) -> int:
    """Reload local Mihomo via 127.0.0.1:9090. Returns HTTP status code (204 on success)."""
    target_config = config_path or (ROOT / 'config.yaml')
    secret = get_controller_secret()
    req = urllib.request.Request(
        f'http://127.0.0.1:{port}/configs?force=true',
        data=json.dumps({'path': str(target_config)}).encode('utf-8'),
        method='PUT',
        headers={
            'Authorization': f'Bearer {secret}',
            'Content-Type': 'application/json',
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return response.status


def reload_remote_peer(
    config_path: Optional[Path] = None,
    timeout: float = 5.0,
    port: int = 2053,
) -> Dict[str, Any]:
    """Reload peer node's Mihomo via its zashboard-gateway reverse proxy (port 2053).

    Does not raise on network/timeout errors to ensure local caller continues cleanly.
    """
    peer_node = 'tebi' if is_pxed_host() else 'pxed'
    peer_ip = get_remote_node_ip(peer_node)
    if peer_ip in ('127.0.0.1', 'localhost'):
        return {
            'peer_node': peer_node,
            'peer_ip': peer_ip,
            'status': None,
            'success': False,
            'error': f"Peer IP resolved to loopback ({peer_ip}), skipping remote call",
        }

    pw = get_panel_password()
    if not pw:
        return {
            'peer_node': peer_node,
            'peer_ip': peer_ip,
            'status': None,
            'success': False,
            'error': "Missing panel password file",
        }

    target_config = (config_path or (ROOT / 'config.yaml')).resolve()
    url = f'http://{peer_ip}:{port}/panel/api/configs?force=true'

    req = urllib.request.Request(
        url,
        data=json.dumps({'path': str(target_config)}).encode('utf-8'),
        method='PUT',
        headers={
            'Authorization': f'Bearer {pw}',
            'Content-Type': 'application/json',
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return {
                'peer_node': peer_node,
                'peer_ip': peer_ip,
                'status': response.status,
                'success': response.status in (200, 204),
                'error': None,
            }
    except Exception as e:
        _LOG.warning("Cluster reload remote peer (%s @ %s) failed: %s", peer_node, peer_ip, e)
        return {
            'peer_node': peer_node,
            'peer_ip': peer_ip,
            'status': getattr(e, 'code', None) if hasattr(e, 'code') else None,
            'success': False,
            'error': str(e),
        }


def reload_cluster(
    config_path: Optional[Path] = None,
    local_timeout: float = 10.0,
    remote_timeout: float = 5.0,
) -> Dict[str, Any]:
    """Reload Mihomo on both local and peer cluster nodes.

    Returns dict with local status and remote status.
    """
    local_node = 'pxed' if is_pxed_host() else 'tebi'
    local_res: Dict[str, Any] = {'node': local_node, 'status': None, 'success': False, 'error': None}
    try:
        status = reload_local(config_path=config_path, timeout=local_timeout)
        local_res['status'] = status
        local_res['success'] = status in (200, 204)
    except Exception as e:
        _LOG.error("Cluster reload local node (%s) failed: %s", local_node, e)
        local_res['error'] = str(e)

    remote_res = reload_remote_peer(config_path=config_path, timeout=remote_timeout)

    return {
        'local': local_res,
        'remote': remote_res,
    }


def reload_live(config_path: Optional[Path] = None) -> int:
    """Drop-in replacement for existing reload_live() functions.

    Performs cluster reload and returns local status code (204).
    If local fails, raises exception as before.
    """
    res = reload_cluster(config_path=config_path)
    if not res['local']['success']:
        err = res['local']['error'] or f"HTTP {res['local']['status']}"
        raise RuntimeError(f"Local reload failed: {err}")
    return res['local']['status']


def main() -> None:
    parser = argparse.ArgumentParser(description="Mihomo cluster live reloader")
    parser.add_argument('--config', type=Path, default=None, help="Path to config.yaml (default: CLASH_ROOT/config.yaml)")
    parser.add_argument('--local-timeout', type=float, default=10.0, help="Local reload timeout in seconds")
    parser.add_argument('--remote-timeout', type=float, default=5.0, help="Remote peer reload timeout in seconds")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
    res = reload_cluster(
        config_path=args.config,
        local_timeout=args.local_timeout,
        remote_timeout=args.remote_timeout,
    )
    loc = res['local']
    rem = res['remote']
    print(
        f"Cluster reload: local={loc.get('status')} ({loc.get('node')}), "
        f"remote={rem.get('status')} ({rem.get('peer_node')}@{rem.get('peer_ip')})"
    )
    if not loc['success']:
        sys.exit(1)


if __name__ == '__main__':
    main()
