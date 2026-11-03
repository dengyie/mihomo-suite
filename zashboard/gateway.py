#!/usr/bin/env python3
import concurrent.futures
import hashlib
import http.client
import http.server
import importlib.util
import json
import mimetypes
import os
import secrets
import select
import socket
import socketserver
import threading
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import parse_qs, urlencode, urlsplit

# Environment variable support for directories and paths
ROOT = Path(os.environ.get('ZASHBOARD_DIST', '/personal/zashboard/dist')).resolve()
UPSTREAM_HOST = os.environ.get('MIHOMO_API_HOST', '127.0.0.1')
UPSTREAM_PORT = int(os.environ.get('MIHOMO_API_PORT', '9090'))

PANEL_PASSWORD_FILE_ENV = os.environ.get('PANEL_PASSWORD_FILE')
PANEL_PASSWORD_FILE = Path(PANEL_PASSWORD_FILE_ENV).resolve() if PANEL_PASSWORD_FILE_ENV else Path('/personal/zashboard/panel.password')

CLASH_ROOT_ENV = os.environ.get('CLASH_ROOT')
CLASH_ROOT = Path(CLASH_ROOT_ENV).resolve() if CLASH_ROOT_ENV else Path('/personal/clash')
RECONCILER_PATH = CLASH_ROOT / 'rules-reconciler.py'
SUBSCRIPTION_MANAGER_PATH = CLASH_ROOT / 'subscription-manager.py'

# The gateway runs on Python 3.10, whose mimetypes table has no .webp entry, so
# the globe textures were served as application/octet-stream. Register it (and
# keep any future image format here) before mimetypes.guess_type is first used.
mimetypes.add_type('image/webp', '.webp')

# Static file byte cache. /personal is NFS, so every uncached request costs a
# full file read round-trip; validate by (mtime_ns, size) so file swaps are
# always picked up. index.html is never rewritten with the panel password.
_STATIC_CACHE = {}
_STATIC_CACHE_MAX_ENTRIES = 64
_STATIC_CACHE_MAX_BYTES = 32 * 1024 * 1024  # bound memory: hashed assets stay on
# disk across deploys, so entry count alone is not a safe bound (dist big JS
# alone is ~1.5MB/file). Cache is wiped wholesale when either bound is hit —
# cheap and self-healing since repopulation is just file reads.
_STATIC_CACHE_LOCK = threading.Lock()

_reconciler_mtime = 0
_reconciler_module = None
_reconciler_lock = threading.Lock()
_sub_manager_mtime = 0
_sub_manager_module = None
_sub_manager_lock = threading.Lock()


class SubManagerLoadError(RuntimeError):
    """Raised when the subscription-manager module cannot be loaded."""


def get_sub_manager():
    global _sub_manager_mtime, _sub_manager_module
    if not SUBSCRIPTION_MANAGER_PATH.exists():
        return None
    current_mtime = os.path.getmtime(SUBSCRIPTION_MANAGER_PATH)
    if _sub_manager_module is not None and current_mtime <= _sub_manager_mtime:
        return _sub_manager_module
    with _sub_manager_lock:
        if _sub_manager_module is not None and current_mtime <= _sub_manager_mtime:
            return _sub_manager_module
        spec = importlib.util.spec_from_file_location("subscription_manager", str(SUBSCRIPTION_MANAGER_PATH))
        if spec is None or spec.loader is None:
            raise SubManagerLoadError(f"Cannot create a module spec/loader for {SUBSCRIPTION_MANAGER_PATH}")
        try:
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
        except Exception as e:
            if _sub_manager_module is None:
                raise SubManagerLoadError(f"Failed to load {SUBSCRIPTION_MANAGER_PATH}: {e!r}") from e
            print(f"Subscription manager reload FAILED; keeping last good module: {e!r}", flush=True)
            _sub_manager_mtime = current_mtime
            return _sub_manager_module
        _sub_manager_module = mod
        _sub_manager_mtime = current_mtime
        return _sub_manager_module


def is_pxed_host() -> bool:
    return os.path.exists('/data/tuntunshu') or 'pxed' in socket.gethostname()


def _etag_matches(if_none_match: str, digest: str) -> bool:
    """True when If-None-Match names this sha256 (quoted, weak, or list)."""
    if not if_none_match or not digest:
        return False
    wanted = {digest, f'"{digest}"', f'W/"{digest}"'}
    for raw in if_none_match.split(','):
        token = raw.strip()
        if token in wanted:
            return True
        if token.startswith('W/') and token[2:].strip() in wanted:
            return True
    return False


def _backfill_edit_payload(payload: dict, existing: list, rule_id: str) -> dict:
    """PUT merges a web-form payload into the stored entry.

    The UI form only edits type/payload/target; fields the form does not know
    about (``params``, e.g. added via API or a later YAML edit) must carry over
    to the new entry instead of being silently dropped. Poisoned placeholder
    values ('' or whitespace) are skipped so they do not clobber a real value.
    """
    entry = next((r for r in existing if r.get('id') == rule_id), None)
    if entry is None:
        return payload
    for field in ('params',):
        if field in payload:
            continue
        value = str(entry.get(field) or '')
        if value.strip():
            payload[field] = entry[field]
    return payload


def get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('10.255.255.255', 1))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return '127.0.0.1'


def record_node_ip():
    try:
        ip = get_local_ip()
        node_name = 'pxed' if is_pxed_host() else 'tebi'
        node_dir = Path(f'/personal/{node_name}')
        node_dir.mkdir(parents=True, exist_ok=True)
        (node_dir / 'internal-ip').write_text(ip)
    except Exception as e:
        print(f"Failed to record node ip: {e}", flush=True)


def get_remote_node_ip(target_node: str) -> str:
    ip_file = Path(f'/personal/{target_node}/internal-ip')
    if ip_file.exists():
        try:
            ip = ip_file.read_text().strip()
            if ip:
                return ip
        except Exception:
            pass
    if target_node == 'pxed':
        return '10.5.103.87'
    if target_node == 'tebi':
        return '10.5.103.26'
    return '127.0.0.1'


class ReconcilerLoadError(RuntimeError):
    """Raised when the reconciler module can NOT be loaded on first import \
    (missing runtime dep such as PyYAML, syntax error, etc). \
    Distinct from "file absent" (which is not an error condition)."""


def get_reconciler():
    """Return the loaded reconciler module, or None if the source file is \
    absent. A *failure to load an existing file* raises :class:`ReconcilerLoadError` \
    instead of silently degrading, so the real cause (missing dep / syntax / \
    permission) surfaces to callers and logs instead of a misleading "unavailable"."""
    global _reconciler_mtime, _reconciler_module
    if not RECONCILER_PATH.exists():
        return None
    current_mtime = os.path.getmtime(RECONCILER_PATH)
    if _reconciler_module is not None and current_mtime <= _reconciler_mtime:
        return _reconciler_module
    with _reconciler_lock:
        if _reconciler_module is not None and current_mtime <= _reconciler_mtime:
            return _reconciler_module
        spec = importlib.util.spec_from_file_location("rules_reconciler", str(RECONCILER_PATH))
        if spec is None or spec.loader is None:
            raise ReconcilerLoadError(
                f"Cannot create a module spec/loader for {RECONCILER_PATH}")
        try:
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
        except Exception as e:
            if _reconciler_module is None:
                # First load failed -> do NOT hide it (this is how the missing
                # PyYAML case went unnoticed in production).
                raise ReconcilerLoadError(
                    f"Failed to load {RECONCILER_PATH}: {e!r}. "
                    "Check runtime deps (e.g. PyYAML) and file syntax.") from e
            # We already hold a known-good module: keep serving it (resilience
            # against a transient reload), but log the reload failure loudly and
            # avoid retrying on every request until the file next changes.
            print(f"Reconciler reload FAILED; keeping last good module: {e!r}", flush=True)
            _reconciler_mtime = current_mtime
            return _reconciler_module
        _reconciler_module = mod
        _reconciler_mtime = current_mtime
        return _reconciler_module


def panel_password():
    """Return the panel API password, or '' if no panel.password file is    \
    configured. No hardcoded default: this gateway must fail closed (deny    \
    /panel/api) rather than expose a well-known credential. The password is    \
    never injected into static HTML."""
    if PANEL_PASSWORD_FILE.exists():
        return PANEL_PASSWORD_FILE.read_text().strip() or ''
    return ''


def consteq(left: str, right: str) -> bool:
    """Length-safe constant-time compare.

    CPython 3.10 ``secrets.compare_digest`` raises ValueError when the
    arguments differ in length; CI runs 3.10. Never compare until both
    sides are non-empty strings of equal length.
    """
    if not isinstance(left, str) or not isinstance(right, str):
        return False
    if not left or not right or len(left) != len(right):
        return False
    return secrets.compare_digest(left, right)


MAX_BODY_BYTES = 1 * 1024 * 1024

# Mihomo controller paths the public panel is allowed to reach through /panel/api.
# Anything else (PUT /configs with an arbitrary path, GET /debug/pprof, ...) is 403.
MIHOMO_PROXY_GET = {
    '/configs',
    '/configs/geo',
    '/connections',
    '/dns/query',
    '/group/weights',
    '/providers/proxies',
    '/providers/rules',
    '/proxies',
    '/rules',
    '/version',
    '/traffic',
    '/logs',
    '/memory',
    '/upgrade',
    '/upgrade/ui',
    '/restart',
}
MIHOMO_PROXY_MUTATE = {
    '/configs',
    '/configs/geo',
    '/connections',
    '/proxies',
    '/providers/proxies',
    '/providers/rules',
    '/restart',
    '/rules/disable',
    '/upgrade',
    '/upgrade/ui',
    '/cache/dns/flush',
    '/cache/fakeip/flush',
    '/cache/smart/flush',
}
MIHOMO_DELAY_URLS = {
    'http://www.gstatic.com/generate_204',
    'https://www.gstatic.com/generate_204',
    'http://1.1.1.1/cdn-cgi/trace',
    'https://1.1.1.1/cdn-cgi/trace',
    'https://cloudflare.com/cdn-cgi/trace',
    'http://www.gstatic.com/generate_204',
}


def _read_request_body(handler, limit: int = MAX_BODY_BYTES) -> bytes:
    raw_len = handler.headers.get('Content-Length', '0') or '0'
    try:
        length = int(raw_len)
    except (TypeError, ValueError):
        raise ValueError('Invalid Content-Length')
    if length < 0:
        raise ValueError('Invalid Content-Length')
    if length > limit:
        raise ValueError(f'Request body exceeds {limit} bytes')
    return handler.rfile.read(length) if length else b''


def _mihomo_path_allowed(method: str, api_p: str) -> bool:
    """Allow only the Clash Meta paths the panel actually uses."""
    if not api_p.startswith('/'):
        api_p = '/' + api_p
    method = method.upper()
    if api_p in STREAM_ENDPOINTS:
        return method in ('GET', 'HEAD', 'OPTIONS')
    if api_p.endswith('/delay') or api_p.endswith('/healthcheck'):
        return method in ('GET', 'HEAD')
    if method in ('GET', 'HEAD', 'OPTIONS'):
        if api_p in MIHOMO_PROXY_GET:
            return True
        # /proxies/<name>, /group/<name>, /providers/proxies/<name>, /connections/<id>
        prefixes = (
            '/proxies/',
            '/group/',
            '/providers/proxies/',
            '/providers/rules/',
            '/connections/',
        )
        return any(api_p.startswith(p) for p in prefixes)
    if method in ('PUT', 'PATCH', 'POST', 'DELETE'):
        if api_p in MIHOMO_PROXY_MUTATE:
            return True
        prefixes = (
            '/proxies/',
            '/providers/proxies/',
            '/providers/rules/',
            '/connections/',
            '/cache/',
        )
        if any(api_p.startswith(p) for p in prefixes):
            if api_p.startswith('/cache/') and not api_p.endswith('/flush'):
                return False
            return True
        return False
    return False


def _sandbox_config_path(raw) -> Optional[Path]:
    """Resolve config_path under CLASH_ROOT. Reject traversal / absolute escapes."""
    if raw is None or raw == '':
        return None
    clash_base = Path(CLASH_ROOT).resolve()
    candidate = Path(str(raw))
    if not candidate.is_absolute():
        candidate = clash_base / candidate
    try:
        resolved = candidate.resolve()
        resolved.relative_to(clash_base)
    except (ValueError, OSError):
        raise ValueError('config_path must stay under CLASH_ROOT')
    if not resolved.is_file():
        raise ValueError('config_path is not a file under CLASH_ROOT')
    return resolved


def _startup_diagnostics():
    """Print a clearly-labelled block of runtime health diagnostics once at  \
    startup so environment drift (wrong interpreter, missing PyYAML, reconciler \
    syntax error) is obvious in the gateway log instead of surfacing only as a \
    500 on first /panel/api user-rules request. Does NOT change run behaviour;  \
    errors are reported, not thrown (the gateway still boots)."""
    try:
        import sys as _sys
        interp = _sys.executable
        pyver = _sys.version.split()[0]
    except Exception:
        interp = pyver = 'unknown'
    try:
        import yaml  # noqa: F401
        yaml_ok = 'yaml@' + getattr(yaml, '__version__', '?')
    except Exception as e:
        yaml_ok = 'MISSING ({!r})'.format(e)
    try:
        rec = get_reconciler()
        rec_ok = 'loaded' if rec is not None else 'absent (NO reconciler file)'
    except ReconcilerLoadError as e:
        rec_ok = 'LOAD ERROR ({!r})'.format(e)
    try:
        sm = get_sub_manager()
        sm_ok = 'loaded' if sm is not None else 'absent (NO subscription manager file)'
    except SubManagerLoadError as e:
        sm_ok = 'LOAD ERROR ({!r})'.format(e)
    print('--- zashboard-gateway startup diagnostics ---', flush=True)
    print('  interpreter  : ' + interp + ' (python ' + pyver + ')', flush=True)
    print('  pyyaml       : ' + yaml_ok, flush=True)
    print('  reconciler   : ' + rec_ok, flush=True)
    print('  sub_manager  : ' + sm_ok, flush=True)
    print('  password file: ' + ('present' if PANEL_PASSWORD_FILE.exists() else "MISSING (fail-closed: '')"), flush=True)
    print('--- end diagnostics ---', flush=True)


STREAM_ENDPOINTS = {'/traffic', '/connections', '/logs', '/memory'}

# ---------------------------------------------------------------------------
# In-memory (stale-while-revalidate) cache for idempotent / re-readable GETs.
# Key = (node, method, api_path, query); nodes are 'local' (this host's own
# mihomo) and 'pxed'/'tebi' (remote node reached over the VPC). caches are
# per-node isolated so we never mix two backends' data. We serve whatever we
# have (even stale) so a transient upstream (pxed VPC) hiccup never snowballs
# into a 10s+ cold <= frontend /version health check timing out; the background
# warmer refreshes every ~10s and mutation invalidation clears on change.
# ---------------------------------------------------------------------------
CACHE_LOCK = threading.Lock()
CACHE = {}
CACHE_FAILS = {}              # node -> consecutive upstream failures
CACHE_MAX_BYTES = 20 * 1024 * 1024
CACHE_MAX_ENTRIES = 512
# If a backend's upstream read fails this many consecutive times, STOP serving
# stale data for it so a genuinely-dead backend surfaces real errors instead of
# being masked forever by stale-while-revalidate. A single successful refetch
# resets the counter (see cache_put).
CACHE_MAX_CONSECUTIVE_FAILS = 5
REFRESH_HEADER = 'X-Zashboard-Refresh'
# Remote (px) nodes have no background warmer (its own host warms it). Without
# a refetch there is no way for the 5xx/transfer-failure path to run, so a
# genuinely dead remote would keep serving stale forever. We revalidate a
# served-but-stale remote entry lazily (only when a client actually reads it)
# in a background thread; the fetch mutates the cache + failure counter the
# same way a live read would. Deduplicated so we never hammer the slow VPC.
REMOTE_REVALIDATE_SECS = 15
_REMOTE_REVALIDATING = set()   # keys in-flight, guarded by CACHE_LOCK


def _is_cacheable(method: str, api_p: str) -> bool:
    if method != 'GET':
        return False
    if api_p in STREAM_ENDPOINTS:          # real-time streams -> never cache
        return False
    if api_p == '/delay' or api_p.endswith('/delay'):
        return False                      # live latency tests
    if api_p.endswith('/healthcheck'):
        return False
    if (api_p.startswith('/user-rules') or api_p.startswith('/storage') or
            api_p.startswith('/diagnostics') or api_p.startswith('/subscriptions') or
            '/simulate' in api_p):
        return False                      # dynamic features & live diagnostics -> never cache
    return True


def cache_get(node: str, method: str, api_p: str, query: str):
    if not _is_cacheable(method, api_p):
        return None
    key = (node, method, api_p, query)
    with CACHE_LOCK:
        # Consecutive-failure guard: if this node just kept failing to reach the
        # upstream, bypass stale so a real outage is reported (and auto-recovers
        # once a refetch succeeds, which clears CACHE_FAILS).
        if CACHE_FAILS.get(node, 0) >= CACHE_MAX_CONSECUTIVE_FAILS:
            return None
        ent = CACHE.get(key)
        if not ent:
            return None
        return ent


def cache_fail(node: str):
    """Record one consecutive upstream failure for a node."""
    with CACHE_LOCK:
        CACHE_FAILS[node] = CACHE_FAILS.get(node, 0) + 1


def cache_put(node: str, method: str, api_p: str, query: str, status: int, headers, body: bytes):
    if not _is_cacheable(method, api_p):
        return
    if len(body) > CACHE_MAX_BYTES:
        return
    key = (node, method, api_p, query)
    with CACHE_LOCK:
        # a successful refetch proves the upstream is reachable again
        CACHE_FAILS.pop(node, None)
        existing = CACHE.get(key)
        # Preserve content-encoding if the upstream response was compressed;
        # serve with the same header so cached bytes decode identically to the
        # live path. (we also force identity upstream, but stay correct anyway)
        if existing is not None:
            CACHE[key] = {**existing, 'ts': time.time(), 'status': status, 'headers': headers, 'body': body}
            return
        if len(CACHE) >= CACHE_MAX_ENTRIES:
            # evict the oldest entry by ts to bound memory on long-running hosts
            try:
                oldest_key = min(CACHE, key=lambda k: CACHE[k]['ts'])
                CACHE.pop(oldest_key, None)
            except ValueError:
                CACHE.clear()
        CACHE[key] = {'ts': time.time(), 'status': status, 'headers': headers, 'body': body}


def cache_invalidate(node: str):
    with CACHE_LOCK:
        for k in [k for k in CACHE if k[0] == node]:
            CACHE.pop(k, None)
        CACHE_FAILS.pop(node, None)


def cache_stats():
    with CACHE_LOCK:
        return len(CACHE)


def api_path(raw_path):
    return urlsplit(raw_path).path.split('/panel/api', 1)[-1] or '/'


def _probe_egress_source(src: Dict[str, Any], timeout: float = 3.5, use_proxy: bool = True, proxy_port: int = 7897) -> Optional[Dict[str, Any]]:
    """Probe a single egress diagnosis source and return parsed network info."""
    req = urllib.request.Request(
        src['url'],
        headers={'User-Agent': 'curl/8.1.2'}
    )
    proxies = {}
    if use_proxy:
        proxies = {
            'http': f'http://127.0.0.1:{proxy_port}',
            'https': f'http://127.0.0.1:{proxy_port}',
        }
        opener = urllib.request.build_opener(urllib.request.ProxyHandler(proxies))
    else:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    with opener.open(req, timeout=timeout) as resp:
        raw = resp.read().decode('utf-8', errors='ignore')
        parsed_info = {}
        if src.get('type') == 'json':
            j = json.loads(raw)
            parsed_info = {
                'ip': j.get('ip') or j.get('query'),
                'country': j.get('country'),
                'city': j.get('city'),
                'region': j.get('region'),
                'org': j.get('org') or j.get('as'),
                'loc': j.get('loc') or (f"{j.get('lat')},{j.get('lon')}" if 'lat' in j else None),
            }
        elif src.get('type') == 'trace':
            trace_dict = dict(line.split('=', 1) for line in raw.strip().split('\n') if '=' in line)
            parsed_info = {
                'ip': trace_dict.get('ip'),
                'country': trace_dict.get('loc'),
                'warp': trace_dict.get('warp'),
                'colo': trace_dict.get('colo'),
            }
        if parsed_info.get('ip'):
            return parsed_info
# Diagnostics thread pool
DIAGNOSTICS_EXECUTOR = concurrent.futures.ThreadPoolExecutor(
    max_workers=8,
    thread_name_prefix='egress-probe'
)


def _is_authenticated(handler) -> bool:
    """Check if the incoming request handler has valid panel authentication."""
    secret = panel_password()
    if not secret:
        # Fail closed: an empty/missing password must NEVER open the panel.
        return False
    value = handler.headers.get('Authorization', '')
    if value:
        prefix = 'Bearer '
        if not value.startswith(prefix):
            return False
        return consteq(value[len(prefix):], secret)
    token = parse_qs(urlsplit(handler.path).query).get('token', [''])[0]
    return bool(token) and consteq(token, secret)


# Backwards compatibility alias if needed by external callers
authorized = _is_authenticated


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def _is_authenticated(self) -> bool:
        return _is_authenticated(self)

    def send_json(self, status: int, data: dict):
        body = json.dumps(data, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _reply_cached(self, ent):
        self.send_response(ent['status'])
        for k, v in ent['headers']:
            self.send_header(k, v)
        self.send_header('Content-Length', str(len(ent['body'])))
        self.end_headers()
        self.wfile.write(ent['body'])

    def _schedule_remote_revalidate(self, node, remote_ip, remote_port,
                                    rel_path, query, api_p):
        """Lazily re-fetch a stale remote entry in the background.

        Remote (px) entries have no permanent warmer (the owning host warms
        itself; we removed cross-VPC polling on purpose to stop 502 spam).
        But stale-while-revalidate would then mask a genuinely dead remote
        forever, because the 5xx/transfer-failure branch is only reached when
        the origin is re-contacted. This dedups + throttles: at most one
        in-flight revalidation per (node, path, query), and only revalidates
        entries older than REMOTE_REVALIDATE_SECS.
        """
        key = (node, 'GET', api_p, query)
        with CACHE_LOCK:
            ent = CACHE.get(key)
            if not ent:
                return False
            if time.time() - ent['ts'] < REMOTE_REVALIDATE_SECS:
                return False  # fresh enough, skip
            if key in _REMOTE_REVALIDATING:
                return False  # already being revalidated
            _REMOTE_REVALIDATING.add(key)

        def _revalidate():
            try:
                self._remote_refetch(node, remote_ip, remote_port,
                                     rel_path + query, api_p, query)
            finally:
                with CACHE_LOCK:
                    _REMOTE_REVALIDATING.discard(key)

        threading.Thread(target=_revalidate, daemon=True).start()
        return True

    def _remote_refetch(self, node, remote_ip, remote_port, path_query,
                        api_p, query):
        """Fetch a remote origin and update cache + failure counter only.

        Never writes to the client socket (runs in a background thread after
        the stale entry has already been served). Keeps the per-node
        consecutive-failure gate alive for remote nodes so a real outage
        eventually breaks through stale-while-revalidate.
        """
        try:
            conn = http.client.HTTPConnection(remote_ip, remote_port, timeout=30)
            try:
                headers = {
                    'Host': f'{remote_ip}:{remote_port}',
                    'Accept-Encoding': 'identity',
                    'Authorization': 'Bearer ' + panel_password(),
                    'Connection': 'close',
                }
                conn.request('GET', path_query, headers=headers)
                resp = conn.getresponse()
                data = resp.read()
                if resp.status == 200:
                    saved = [(k, v) for k, v in resp.getheaders()
                             if k.lower() in ('content-type', 'content-encoding', 'vary')]
                    cache_put(node, 'GET', api_p, query, 200, saved, data)
                elif resp.status >= 500:
                    cache_fail(node)
            finally:
                conn.close()
        except Exception:
            cache_fail(node)

    def _handle_subscriptions(self, method: str, rel_path: str):
        if not self._is_authenticated():
            self.send_response(401)
            self.send_header('Content-Length', '0')
            self.send_header('WWW-Authenticate', 'Bearer')
            self.end_headers()
            return

        try:
            sm = get_sub_manager()
        except SubManagerLoadError as e:
            self.send_json(500, {'status': 'error', 'error': f'Subscription manager module failed to load: {e}'})
            return
        if not sm:
            self.send_json(500, {'status': 'error', 'error': 'Subscription manager module is unavailable'})
            return

        engine = sm.SubscriptionEngine()
        subpath = rel_path[len('/panel/api/subscriptions'):].strip('/')
        parts = [p for p in subpath.split('/') if p]

        try:
            body_bytes = _read_request_body(self)
        except ValueError as e:
            self.send_json(413 if 'exceeds' in str(e) else 400, {'status': 'error', 'error': str(e)})
            return
        payload = {}
        if body_bytes:
            try:
                payload = json.loads(body_bytes.decode('utf-8'))
            except Exception as e:
                self.send_json(400, {'status': 'error', 'error': f'Invalid JSON body: {e}'})
                return

        # GET /panel/api/subscriptions -> list subscriptions
        if method == 'GET' and len(parts) == 0:
            subs = engine.list_subscriptions()
            self.send_json(200, {'status': 'ok', 'data': {'subscriptions': subs}})
            return

        # POST /panel/api/subscriptions/import-nodes
        if method == 'POST' and len(parts) == 1 and parts[0] == 'import-nodes':
            name = payload.get('name', 'imported-nodes')
            raw_text = payload.get('text') or payload.get('raw_content') or payload.get('content') or ''
            if not raw_text:
                self.send_json(400, {'status': 'error', 'error': 'Missing raw text / content for import'})
                return
            exclude_filter = payload.get('exclude_filter')
            if exclude_filter is not None and not str(exclude_filter).strip():
                exclude_filter = None
            skip_merge = payload.get('skip_merge', True)
            inject_local = payload.get('inject_local', True)
            probe = payload.get('probe', True)
            target_group = payload.get('target_group')
            res = engine.import_raw_nodes(
                name=name,
                raw_text=raw_text,
                exclude_filter=exclude_filter,
                skip_merge=bool(skip_merge),
                inject_local=bool(inject_local),
                probe=bool(probe),
                target_group=target_group,
            )
            if res.get('success'):
                cache_invalidate('local')
                self.send_json(200, {'status': 'ok', 'data': res})
            else:
                self.send_json(400, {'status': 'error', 'error': res.get('error', 'Import failed'), 'data': res})
            return

        # POST /panel/api/subscriptions -> add subscription
        if method == 'POST' and len(parts) == 0:
            name = payload.get('name')
            if not name:
                self.send_json(400, {'status': 'error', 'error': "Missing required field 'name'"})
                return
            url = payload.get('url')
            raw_content = payload.get('raw_content') or payload.get('content')
            sub_type = payload.get('type', 'remote' if url else 'raw')
            exclude_filter = payload.get('exclude_filter')
            if exclude_filter is not None and not str(exclude_filter).strip():
                exclude_filter = None
            enabled = payload.get('enabled', True)
            skip_merge = payload.get('skip_merge', True)
            inject_local = payload.get('inject_local', True)
            probe = payload.get('probe', True)
            target_group = payload.get('target_group')

            res = engine.add_subscription(
                name=name,
                url=url,
                sub_type=sub_type,
                raw_content=raw_content,
                exclude_filter=exclude_filter,
                enabled=enabled,
                skip_merge=bool(skip_merge),
                inject_local=bool(inject_local),
                probe=bool(probe),
                target_group=target_group,
            )
            if res.get('success'):
                cache_invalidate('local')
                self.send_json(200, {'status': 'ok', 'data': res})
            else:
                err = res.get('error', 'Add failed')
                code = 502 if str(err).startswith('Fetch failed') else 400
                self.send_json(code, {'status': 'error', 'error': err, 'data': res})
            return

        # POST /panel/api/subscriptions/<sub_id>/update
        if method == 'POST' and len(parts) == 2 and parts[1] == 'update':
            sub_id = parts[0]
            name = payload.get('name')
            url = payload.get('url')
            raw_content = payload.get('raw_content')
            exclude_filter = payload.get('exclude_filter')
            enabled = payload.get('enabled')
            refresh = payload.get('refresh', True)
            inject_local = payload.get('inject_local')
            probe = payload.get('probe', True)

            res = engine.update_subscription(
                sub_id=sub_id,
                name=name,
                url=url,
                raw_content=raw_content,
                exclude_filter=exclude_filter,
                enabled=enabled,
                refresh=refresh,
                inject_local=None if inject_local is None else bool(inject_local),
                probe=bool(probe),
            )
            if res.get('success'):
                cache_invalidate('local')
                self.send_json(200, {'status': 'ok', 'data': res})
            else:
                err = res.get('error', 'Update failed')
                err_l = err.lower()
                if 'not found' in err_l:
                    code = 404
                elif str(err).startswith('Fetch failed'):
                    code = 502
                else:
                    code = 400
                self.send_json(code, {
                    'status': 'error',
                    'error': err,
                    'data': res,
                })
            return

        # POST /panel/api/subscriptions/<sub_id>/toggle
        if method == 'POST' and len(parts) == 2 and parts[1] == 'toggle':
            sub_id = parts[0]
            subs = engine.list_subscriptions()
            sub = next((s for s in subs if s.get('id') == sub_id), None)
            if not sub:
                self.send_json(404, {'status': 'error', 'error': f"Subscription '{sub_id}' not found"})
                return

            new_enabled = not sub.get('enabled', True)
            if 'enabled' in payload:
                new_enabled = bool(payload['enabled'])

            res = engine.update_subscription(
                sub_id=sub_id,
                enabled=new_enabled,
                refresh=False,
            )
            if res.get('success'):
                cache_invalidate('local')
                self.send_json(200, {'status': 'ok', 'data': res})
            else:
                self.send_json(400, {'status': 'error', 'error': res.get('error', 'Toggle failed'), 'data': res})
            return

        # PATCH /panel/api/subscriptions/<sub_id> (Standard REST partial update)
        if method == 'PATCH' and len(parts) == 1:
            sub_id = parts[0]
            name = payload.get('name')
            url = payload.get('url')
            raw_content = payload.get('raw_content')
            exclude_filter = payload.get('exclude_filter')
            enabled = payload.get('enabled')
            refresh = payload.get('refresh', False)
            target_group = payload.get('target_group')

            res = engine.update_subscription(
                sub_id=sub_id,
                name=name,
                url=url,
                raw_content=raw_content,
                exclude_filter=exclude_filter,
                enabled=enabled,
                refresh=refresh,
                target_group=target_group,
            )
            if res.get('success'):
                cache_invalidate('local')
                self.send_json(200, {'status': 'ok', 'data': res})
            else:
                err = res.get('error', 'Update failed')
                err_l = err.lower()
                if 'not found' in err_l:
                    code = 404
                elif str(err).startswith('Fetch failed'):
                    code = 502
                else:
                    code = 400
                self.send_json(code, {
                    'status': 'error',
                    'error': err,
                    'data': res,
                })
            return

        # DELETE /panel/api/subscriptions/<sub_id>
        if method == 'DELETE' and len(parts) == 1:
            sub_id = parts[0]
            res = engine.delete_subscription(sub_id)
            if res.get('success'):
                cache_invalidate('local')
                self.send_json(200, {'status': 'ok', 'data': res})
            else:
                self.send_json(404, {'status': 'error', 'error': res.get('error', 'Delete failed'), 'data': res})
            return

        self.send_json(405, {'status': 'error', 'error': f'Method {method} not allowed for path {rel_path}'})

    def _client_sub_token_ok(self, engine) -> bool:
        """Clash Verge cannot send Authorization; authenticate ?token= against
        the dedicated client-export token (or PANEL_PASSWORD as a fallback).
        Empty tokens never match.
        """
        token = parse_qs(urlsplit(self.path).query).get('token', [''])[0]
        if not token:
            return False
        expected = ''
        try:
            expected = engine.get_or_create_client_token()
        except Exception:
            expected = ''
        if expected and consteq(token, expected):
            return True
        panel = panel_password()
        return bool(panel) and consteq(token, panel)

    def _handle_client_sub(self, method: str):
        """Public Clash client YAML: GET /sub/clash?token=...

        Outside /panel/api so Clash Verge can fetch without a Bearer header.
        Never fetch remotes on this path (use cached merge) so a client poll
        cannot turn into an outbound SSRF amplifier.
        """
        if method not in ('GET', 'HEAD'):
            self.send_json(405, {'status': 'error', 'error': f'Method {method} not allowed'})
            return
        try:
            sm = get_sub_manager()
        except SubManagerLoadError as e:
            self.send_json(500, {'status': 'error', 'error': f'Subscription manager module failed to load: {e}'})
            return
        if not sm:
            self.send_json(500, {'status': 'error', 'error': 'Subscription manager module is unavailable'})
            return
        engine = sm.SubscriptionEngine()
        if not self._client_sub_token_ok(engine):
            self.send_response(401)
            self.send_header('Content-Length', '0')
            self.send_header('WWW-Authenticate', 'Bearer')
            self.end_headers()
            return
        try:
            published = engine.publish_client_clash_config(fetch_remote=False)
        except sm.ClientExportInvalid as e:
            self.send_json(500, {'status': 'error', 'error': str(e), 'errors': e.errors})
            return
        except Exception as e:
            self.send_json(500, {'status': 'error', 'error': str(e)})
            return
        yaml_text = published.get('yaml') or ''
        body = yaml_text.encode('utf-8')
        digest = str(published.get('sha256') or '')
        etag = f'"{digest}"' if digest else None
        if published.get('served_last_good'):
            print(
                'mango-clash serving last-good sha256=%s errors=%s'
                % (digest[:12], '; '.join(str(e) for e in (published.get('errors') or [])[:4])),
                flush=True,
            )
        if etag:
            inm = (self.headers.get('If-None-Match') or '').strip()
            if _etag_matches(inm, digest):
                self.send_response(304)
                self.send_header('ETag', etag)
                self.send_header('Cache-Control', 'private, max-age=0, must-revalidate')
                self.send_header('profile-title', 'mango-clash')
                if published.get('served_last_good'):
                    self.send_header('X-Mango-Clash-Stale', '1')
                self.send_header('Content-Length', '0')
                self.end_headers()
                return
        self.send_response(200)
        self.send_header('Content-Type', 'text/yaml; charset=utf-8')
        # Unquoted filename token. Clash Verge copies this header into the
        # remote profile name; a quoted RFC 2183 value becomes a literal
        # backslash-quote in the Verge UI.
        self.send_header('Content-Disposition', 'attachment; filename=mango-clash')
        self.send_header('profile-title', 'mango-clash')
        self.send_header('Cache-Control', 'private, max-age=0, must-revalidate')
        if etag:
            self.send_header('ETag', etag)
        if published.get('served_last_good'):
            self.send_header('X-Mango-Clash-Stale', '1')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        if method != 'HEAD':
            self.wfile.write(body)

    def _handle_client_sub_info(self, method: str, rel_path: str):
        """Authenticated helper: return the Clash client subscription URL/token."""
        if not self._is_authenticated():
            self.send_response(401)
            self.send_header('Content-Length', '0')
            self.send_header('WWW-Authenticate', 'Bearer')
            self.end_headers()
            return
        if method != 'GET':
            self.send_json(405, {'status': 'error', 'error': f'Method {method} not allowed'})
            return
        try:
            sm = get_sub_manager()
        except SubManagerLoadError as e:
            self.send_json(500, {'status': 'error', 'error': f'Subscription manager module failed to load: {e}'})
            return
        if not sm:
            self.send_json(500, {'status': 'error', 'error': 'Subscription manager module is unavailable'})
            return
        engine = sm.SubscriptionEngine()
        token = engine.get_or_create_client_token()
        self.send_json(200, {
            'status': 'ok',
            'data': {
                'path': '/sub/clash',
                'token': token,
                'url_path': f'/sub/clash?token={token}',
            },
        })

    def _handle_diagnostics(self, method: str, rel_path: str):
        if not self._is_authenticated():
            self.send_response(401)
            self.send_header('Content-Length', '0')
            self.send_header('WWW-Authenticate', 'Bearer')
            self.end_headers()
            return

        subpath = rel_path[len('/panel/api/diagnostics'):].strip('/')
        if subpath == 'prune-dead-nodes' and method == 'POST':
            query_params = parse_qs(urlsplit(self.path).query)
            max_workers_str = query_params.get('max_workers', ['5'])[0]
            dry_run_str = query_params.get('dry_run', ['false'])[0].lower()
            max_workers = int(max_workers_str) if max_workers_str.isdigit() else 5
            max_workers = max(1, min(max_workers, 16))
            dry_run = dry_run_str in ('true', '1', 'yes')

            try:
                sm = get_sub_manager()
            except SubManagerLoadError as e:
                self.send_json(500, {'status': 'error', 'error': f'Subscription engine load error: {e}'})
                return
            if not sm:
                self.send_json(500, {'status': 'error', 'error': 'Subscription manager module is unavailable'})
                return

            try:
                engine = sm.SubscriptionEngine()
                res = engine.prune_local_node_file(
                    max_workers=max_workers,
                    apply_filter=not dry_run,
                )
                if res.get('success'):
                    cache_invalidate('local')
                    self.send_json(200, {'status': 'ok', 'data': res})
                else:
                    self.send_json(500, {'status': 'error', 'error': res.get('error', 'Prune failed'), 'data': res})
            except Exception as e:
                self.send_json(500, {'status': 'error', 'error': str(e)})
            return

        if subpath == 'egress-ip' and method == 'GET':
            query_params = parse_qs(urlsplit(self.path).query)
            proxy_port_str = query_params.get('proxy_port', ['7897'])[0]
            use_proxy_str = query_params.get('proxy', ['true'])[0].lower()
            use_proxy = use_proxy_str not in ('false', '0', 'no')
            proxy_port = int(proxy_port_str) if proxy_port_str.isdigit() else 7897

            # Probe targets for multi-source race detection
            sources = [
                {'name': 'ipinfo.io', 'url': 'https://ipinfo.io/json', 'type': 'json'},
                {'name': 'cloudflare', 'url': 'https://cloudflare.com/cdn-cgi/trace', 'type': 'trace'},
                {'name': 'api.ipify.org', 'url': 'https://api.ipify.org?format=json', 'type': 'json'},
                {'name': 'ip-api.com', 'url': 'http://ip-api.com/json', 'type': 'json'},
            ]

            def probe(src):
                start_t = time.perf_counter()
                try:
                    parsed_info = _probe_egress_source(src, timeout=6.5, use_proxy=use_proxy, proxy_port=proxy_port)
                    latency_ms = round((time.perf_counter() - start_t) * 1000, 2)
                    if parsed_info and parsed_info.get('ip'):
                        return {
                            'source': src['name'],
                            'latency_ms': latency_ms,
                            'data': parsed_info,
                        }
                except Exception:
                    pass
                return None

            results = []
            futures = [DIAGNOSTICS_EXECUTOR.submit(probe, src) for src in sources]
            try:
                for future in concurrent.futures.as_completed(futures, timeout=6.5):
                    res = future.result()
                    if res:
                        results.append(res)
            except TimeoutError:
                pass
            except Exception:
                pass

            if not results:
                self.send_json(200, {
                    'status': 'ok',
                    'data': {
                        'success': False,
                        'message': 'All egress probes failed or timed out. Proxy may be offline.',
                        'use_proxy': use_proxy,
                        'proxy_port': proxy_port,
                        'fastest': None,
                        'all_results': [],
                    }
                })
                return

            results.sort(key=lambda x: x['latency_ms'])
            fastest = results[0]

            self.send_json(200, {
                'status': 'ok',
                'data': {
                    'success': True,
                    'use_proxy': use_proxy,
                    'proxy_port': proxy_port,
                    'fastest': fastest,
                    'all_results': results,
                }
            })
            return

        self.send_json(405, {'status': 'error', 'error': f'Method {method} not allowed for {rel_path}'})

    def _handle_rules_simulate(self, method: str, rel_path: str):
        if not self._is_authenticated():
            self.send_response(401)
            self.send_header('Content-Length', '0')
            self.send_header('WWW-Authenticate', 'Bearer')
            self.end_headers()
            return

        if method not in ('GET', 'POST'):
            self.send_json(405, {'status': 'error', 'error': f'Method {method} not allowed'})
            return

        try:
            reconciler = get_reconciler()
        except ReconcilerLoadError as e:
            self.send_json(500, {'status': 'error', 'error': f'Rules reconciler module failed to load: {e}'})
            return
        if not reconciler:
            self.send_json(500, {'status': 'error', 'error': 'Rules reconciler module is unavailable'})
            return

        domain = ''
        config_path = None

        if method == 'GET':
            parsed = urllib.parse.urlparse(self.path)
            qs = urllib.parse.parse_qs(parsed.query)
            domain = (qs.get('domain') or qs.get('query') or [''])[0]
            raw_cfg = (qs.get('config_path') or [None])[0]
        else:
            try:
                body_bytes = _read_request_body(self)
            except ValueError as e:
                self.send_json(413 if 'exceeds' in str(e) else 400, {'status': 'error', 'error': str(e)})
                return
            payload = {}
            if body_bytes:
                try:
                    payload = json.loads(body_bytes.decode('utf-8'))
                except Exception as e:
                    self.send_json(400, {'status': 'error', 'error': f'Invalid JSON body: {e}'})
                    return
            domain = payload.get('domain', '')
            raw_cfg = payload.get('config_path')

        if raw_cfg:
            try:
                config_path = _sandbox_config_path(raw_cfg)
            except ValueError as e:
                self.send_json(400, {'status': 'error', 'error': str(e)})
                return

        if not domain or not isinstance(domain, str):
            self.send_json(400, {'status': 'error', 'error': "Missing or invalid required field 'domain'"})
            return

        res = reconciler.simulate_routing(domain.strip(), config_path)
        self.send_json(200 if res.get('success') else 400, {'status': 'ok' if res.get('success') else 'error', 'data': res})
        return

    def _handle_user_rules(self, method: str, rel_path: str):
        if not self._is_authenticated():
            self.send_response(401)
            self.send_header('Content-Length', '0')
            self.send_header('WWW-Authenticate', 'Bearer')
            self.end_headers()
            return

        try:
            reconciler = get_reconciler()
        except ReconcilerLoadError as e:
            # Do NOT hide the real load failure (missing dep / syntax / spec).
            self.send_json(500, {'error': f'Rules reconciler module failed to load: {e}'})
            return
        if not reconciler:
            self.send_json(500, {'error': 'Rules reconciler module is unavailable'})
            return

        subpath = rel_path[len('/panel/api/user-rules'):].strip('/')

        if method == 'GET':
            if subpath == 'targets':
                targets = sorted(list(reconciler.get_available_targets()))
                self.send_json(200, {'targets': targets})
                return
            data = reconciler.load_user_rules()
            targets = sorted(list(reconciler.get_available_targets()))
            self.send_json(200, {
                'version': data.get('version', 1),
                'rules': data.get('rules', []),
                'available_targets': targets,
            })
            return

        try:
            body_bytes = _read_request_body(self)
        except ValueError as e:
            self.send_json(413 if 'exceeds' in str(e) else 400, {'error': str(e)})
            return
        payload = {}
        if body_bytes:
            try:
                payload = json.loads(body_bytes.decode('utf-8'))
            except Exception as e:
                self.send_json(400, {'error': f'Invalid JSON body: {e}'})
                return

        if method == 'POST':
            if subpath == 'reconcile':
                res = reconciler.reconcile()
                if res.get('success'):
                    cache_invalidate('local')
                self.send_json(200 if res.get('success') else 500, res)
                return
            if not isinstance(payload, dict):
                self.send_json(400, {'error': 'Payload must be a JSON object'})
                return
            if 'id' not in payload:
                payload['id'] = f"user-{secrets.token_hex(6)}"
            res = reconciler.add_or_update_rule(payload)
            if res.get('success'):
                cache_invalidate('local')
            self.send_json(200 if res.get('success') else 400, res)
            return

        if method == 'PUT':
            if not subpath:
                self.send_json(400, {'error': 'Missing rule ID in path'})
                return
            rule_id = subpath
            if not isinstance(payload, dict):
                self.send_json(400, {'error': 'Payload must be a JSON object'})
                return
            # PUT is an update, not an upsert: editing a rule that was already
            # deleted must surface a 404 instead of silently recreating it.
            # (Best-effort guard: the read here and the write below are not
            # atomic, but this panel has a single operator, so a racing delete
            # landing in the window is not a concern.)
            existing = reconciler.load_user_rules().get('rules', [])
            if not any(r.get('id') == rule_id for r in existing):
                self.send_json(404, {'error': f"Rule ID '{rule_id}' not found"})
                return
            payload['id'] = rule_id
            payload = _backfill_edit_payload(payload, existing, rule_id)
            res = reconciler.add_or_update_rule(payload)
            self.send_json(200 if res.get('success') else 400, res)
            return

        if method == 'PATCH':
            if not subpath:
                self.send_json(400, {'error': 'Missing rule ID in path'})
                return
            rule_id = subpath
            if not isinstance(payload, dict):
                self.send_json(400, {'error': 'Payload must be a JSON object'})
                return
            data = reconciler.load_user_rules()
            rules = data.get('rules', [])
            target_rule = next((r for r in rules if r.get('id') == rule_id), None)
            if not target_rule:
                self.send_json(404, {'error': f"Rule ID '{rule_id}' not found"})
                return
            target_rule.update(payload)
            target_rule['id'] = rule_id
            res = reconciler.add_or_update_rule(target_rule)
            if res.get('success'):
                cache_invalidate('local')
            self.send_json(200 if res.get('success') else 400, res)
            return

        if method == 'DELETE':
            if not subpath:
                self.send_json(400, {'error': 'Missing rule ID in path'})
                return
            rule_id = subpath
            res = reconciler.delete_rule(rule_id)
            if res.get('success'):
                cache_invalidate('local')
            self.send_json(200 if res.get('success') else 404, res)
            return

        self.send_json(405, {'error': f'Method {method} not allowed'})

    def _proxy(self, method: str, rel_path: str):
        if not self._is_authenticated():
            self.send_response(401)
            self.send_header('Content-Length', '0')
            self.send_header('WWW-Authenticate', 'Bearer')
            self.end_headers()
            return
        api_p = api_path(rel_path)
        if not _mihomo_path_allowed(method, api_p):
            self.send_json(403, {'status': 'error', 'error': f'Mihomo path not allowed: {method} {api_p}'})
            return
        if api_p in STREAM_ENDPOINTS and self.headers.get('Upgrade', '').lower() != 'websocket':
            self.send_response(426)
            self.send_header('Content-Length', '0')
            self.send_header('Upgrade', 'websocket')
            self.end_headers()
            return

        if method not in ('GET', 'HEAD', 'OPTIONS'):
            cache_invalidate('local')

        # Path: /panel/api/<clash-api-path> -> localhost:9090/<path>
        suffix = rel_path[len('/panel/api'):]
        query_params = parse_qs(urlsplit(self.path).query)
        if suffix.endswith('/delay') or suffix.endswith('/healthcheck'):
            test_url = query_params.get('url', [''])[0]
            if test_url in (
                'http://www.gstatic.com/generate_204',
                'https://www.gstatic.com/generate_204',
                'http://1.1.1.1/cdn-cgi/trace',
                'https://1.1.1.1/cdn-cgi/trace',
            ):
                query_params['url'] = ['https://cloudflare.com/cdn-cgi/trace']
                test_url = 'https://cloudflare.com/cdn-cgi/trace'
            if test_url and test_url not in MIHOMO_DELAY_URLS:
                self.send_json(403, {'status': 'error', 'error': 'delay url is not allowlisted'})
                return
        query = ('?' + urlencode(query_params, doseq=True)) if query_params else ''
        target = suffix or '/'

        # Cache fast-path for re-readable GETs (skip on refresh header).
        if method == 'GET' and target not in STREAM_ENDPOINTS and not suffix.endswith(('/delay', '/healthcheck')):
            refresh = self.headers.get(REFRESH_HEADER, '') == '1'
            api_p = api_path(rel_path)
            ent = None if refresh else cache_get('local', method, api_p, query)
            if ent is not None:
                self._reply_cached(ent)
                return

        conn = http.client.HTTPConnection(UPSTREAM_HOST, UPSTREAM_PORT, timeout=30)
        headers = {k: v for k, v in self.headers.items() if k.lower() not in ('host', 'connection', 'content-length')}
        # Never request a compressed body from upstream: we may cache it and
        # replay it without re-fetching, and the cache only preserves a fixed
        # header subset. Forcing identity keeps cached bytes self-describing.
        headers.pop('Accept-Encoding', None)
        headers['Accept-Encoding'] = 'identity'
        headers['Host'] = f'{UPSTREAM_HOST}:{UPSTREAM_PORT}'
        controller_secret = ''
        secret_file = CLASH_ROOT / '.controller-secret'
        if secret_file.exists():
            controller_secret = secret_file.read_text().strip()
        headers['Authorization'] = 'Bearer ' + controller_secret
        try:
            body = _read_request_body(self)
        except ValueError as e:
            self.send_json(413 if 'exceeds' in str(e) else 400, {'status': 'error', 'error': str(e)})
            return
        body = body or None
        try:
            conn.request(method, target + query, body=body, headers=headers)
            resp = conn.getresponse()
            data = resp.read()
            if method == 'GET' and target not in STREAM_ENDPOINTS and not suffix.endswith(('/delay', '/healthcheck')):
                if resp.status == 200:
                    saved_headers = [(k, v) for k, v in resp.getheaders()
                                     if k.lower() in ('content-type', 'content-encoding', 'vary')]
                    cache_put('local', method, api_path(rel_path), query, resp.status, saved_headers, data)
                elif resp.status >= 500:
                    # A reachable-but-5xx backend is still a backend failure:
                    # count it so stale stops being served and the real error
                    # surfaces, then auto-recovers on the next success.
                    cache_fail('local')
        except Exception as e:
            # Only a failure to reach/read the UPSTREAM counts as a backend
            # failure. Writing to a disconnecting client must NOT do so.
            cache_fail('local')
            self.send_error(502, str(e))
            return
        finally:
            conn.close()
        try:
            self.send_response(resp.status)
            for k, v in resp.getheaders():
                if k.lower() not in ('connection', 'transfer-encoding', 'content-length'):
                    self.send_header(k, v)
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except (ConnectionResetError, BrokenPipeError):
            return  # client went away; not an upstream failure
        except Exception as e:
            self.send_error(502, str(e))

    def _websocket(self, rel_path: str):
        if not self._is_authenticated():
            self.send_response(401)
            self.send_header('Content-Length', '0')
            self.end_headers()
            return
        api_p = api_path(rel_path)
        if api_p not in STREAM_ENDPOINTS:
            self.send_json(403, {'status': 'error', 'error': f'WebSocket path not allowed: {api_p}'})
            return
        upstream = socket.create_connection((UPSTREAM_HOST, UPSTREAM_PORT), timeout=10)
        try:
            path = rel_path[len('/panel/api'):]
            controller_secret = ''
            secret_file = CLASH_ROOT / '.controller-secret'
            if secret_file.exists():
                controller_secret = secret_file.read_text().strip()
            upstream_query = {'token': controller_secret}
            lines = [f'GET {path or "/"}?{urlencode(upstream_query)} HTTP/1.1',
                     f'Host: {UPSTREAM_HOST}:{UPSTREAM_PORT}',
                     'Connection: Upgrade',
                     'Upgrade: websocket',
                     'Authorization: Bearer ' + controller_secret]
            for key, value in self.headers.items():
                if key.lower() not in ('host', 'connection', 'upgrade', 'authorization'):
                    lines.append(f'{key}: {value}')
            upstream.sendall(('\r\n'.join(lines) + '\r\n\r\n').encode())
            response = b''
            while b'\r\n\r\n' not in response:
                chunk = upstream.recv(4096)
                if not chunk:
                    break
                response += chunk
            self.connection.sendall(response)
            if b' 101 ' not in response:
                return
            self.connection.setblocking(False)
            upstream.setblocking(False)
            sockets = [self.connection, upstream]
            while True:
                readable, _, exceptional = select.select(sockets, [], sockets, 60)
                if exceptional or not readable:
                    break
                for source in readable:
                    data = source.recv(65536)
                    if not data:
                        return
                    target = upstream if source is self.connection else self.connection
                    target.sendall(data)
        except Exception:
            return
        finally:
            upstream.close()

    def _forward_remote_http(self, method: str, remote_ip: str, remote_port: int, remote_path_with_query: str, node: str):
        if not self._is_authenticated():
            self.send_response(401)
            self.send_header('Content-Length', '0')
            self.send_header('WWW-Authenticate', 'Bearer')
            self.end_headers()
            return

        rel_path = remote_path_with_query.split('?', 1)[0]
        raw_query = remote_path_with_query.split('?', 1)[1] if '?' in remote_path_with_query else ''
        query = ('?' + raw_query) if raw_query else ''

        if method not in ('GET', 'HEAD', 'OPTIONS'):
            cache_invalidate(node)


        if method == 'GET' and not rel_path.endswith(('/delay', '/healthcheck')):
            refresh = self.headers.get(REFRESH_HEADER, '') == '1'
            api_p = api_path(rel_path)
            ent = None if refresh else cache_get(node, method, api_p, query)
            if ent is not None:
                self._reply_cached(ent)
                # Stale remote entry just served: revalidate it in the
                # background so a dead/failing remote is surfaced instead of
                # being masked forever by stale-while-revalidate. Demand-driven
                # + deduplicated, so it only refetches when actually read.
                self._schedule_remote_revalidate(node, remote_ip, remote_port,
                                                 rel_path, query, api_p)
                return

        conn = http.client.HTTPConnection(remote_ip, remote_port, timeout=30)
        headers = {k: v for k, v in self.headers.items() if k.lower() not in ('host', 'connection', 'content-length')}
        headers.pop('Accept-Encoding', None)
        headers['Accept-Encoding'] = 'identity'
        headers['Host'] = f'{remote_ip}:{remote_port}'
        # Ensure valid inter-gateway authentication across the cluster (tebi <-> pxed)
        # Defense-in-depth: only attach gateway secret if the incoming request is already authenticated
        if self._is_authenticated():
            pw = panel_password()
            if pw:
                headers['Authorization'] = 'Bearer ' + pw
        try:
            body = _read_request_body(self)
        except ValueError as e:
            self.send_json(413 if 'exceeds' in str(e) else 400, {'status': 'error', 'error': str(e)})
            return
        body = body or None
        try:
            conn.request(method, remote_path_with_query, body=body, headers=headers)
            resp = conn.getresponse()
            data = resp.read()
            if method == 'GET' and not rel_path.endswith(('/delay', '/healthcheck')):
                if resp.status == 200:
                    saved_headers = [(k, v) for k, v in resp.getheaders()
                                     if k.lower() in ('content-type', 'content-encoding', 'vary')]
                    cache_put(node, method, api_path(rel_path), query, resp.status, saved_headers, data)
                elif resp.status >= 500:
                    # Reachable-but-5xx upstream counts as a failure too, so
                    # stale stops once the gate trips and recovers on next 200.
                    cache_fail(node)
        except Exception as e:
            # Only a failure to reach/read the remote gateway counts as a
            # backend failure; a client that disconnects mid-write must not.
            cache_fail(node)
            self.send_error(502, f"Remote gateway error ({remote_ip}:{remote_port}): {e}")
            return
        finally:
            conn.close()
        try:
            self.send_response(resp.status)
            for k, v in resp.getheaders():
                if k.lower() not in ('connection', 'transfer-encoding', 'content-length'):
                    self.send_header(k, v)
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except (ConnectionResetError, BrokenPipeError):
            return  # client went away; not an upstream failure
        except Exception as e:
            self.send_error(502, f"Remote gateway error ({remote_ip}:{remote_port}): {e}")

    def _forward_remote_ws(self, remote_ip: str, remote_port: int, remote_path_with_query: str):
        if not self._is_authenticated():
            self.send_response(401)
            self.send_header('Content-Length', '0')
            self.end_headers()
            return
        upstream = socket.create_connection((remote_ip, remote_port), timeout=10)
        try:
            lines = [f'GET {remote_path_with_query} HTTP/1.1',
                     f'Host: {remote_ip}:{remote_port}',
                     'Connection: Upgrade',
                     'Upgrade: websocket']
            for key, value in self.headers.items():
                if key.lower() not in ('host', 'connection', 'upgrade'):
                    lines.append(f'{key}: {value}')
            if not any(k.lower() == 'authorization' for k in self.headers):
                lines.append('Authorization: Bearer ' + panel_password())
            upstream.sendall(('\r\n'.join(lines) + '\r\n\r\n').encode())
            response = b''
            while b'\r\n\r\n' not in response:
                chunk = upstream.recv(4096)
                if not chunk:
                    break
                response += chunk
            self.connection.sendall(response)
            if b' 101 ' not in response:
                return
            self.connection.setblocking(False)
            upstream.setblocking(False)
            sockets = [self.connection, upstream]
            while True:
                readable, _, exceptional = select.select(sockets, [], sockets, 60)
                if exceptional or not readable:
                    break
                for source in readable:
                    data = source.recv(65536)
                    if not data:
                        return
                    target = upstream if source is self.connection else self.connection
                    target.sendall(data)
        except Exception:
            return
        finally:
            upstream.close()

    def _dispatch(self, method: str, is_ws: bool = False, is_head: bool = False):
        raw_path = self.path
        path = raw_path.split('?', 1)[0]
        query = ('?' + raw_path.split('?', 1)[1]) if '?' in raw_path else ''

        target_node = 'local'
        rel_path = path

        if path.startswith('/panel/pxed/api'):
            target_node = 'pxed'
            rel_path = '/panel/api' + path[len('/panel/pxed/api'):]
        elif path.startswith('/panel/tebi/api'):
            target_node = 'tebi'
            rel_path = '/panel/api' + path[len('/panel/tebi/api'):]
        elif path.startswith('/panel/api'):
            target_node = 'local'
            rel_path = path

        is_remote = (target_node == 'pxed' and not is_pxed_host()) or (target_node == 'tebi' and is_pxed_host())

        if is_remote:
            remote_ip = get_remote_node_ip(target_node)
            remote_port = 2053
            if is_ws:
                return self._forward_remote_ws(remote_ip, remote_port, rel_path + query)
            if method == 'OPTIONS':
                self.send_response(204)
                self.end_headers()
                return
            return self._forward_remote_http(method, remote_ip, remote_port, rel_path + query, target_node)

        # Local handling
        if is_ws:
            return self._websocket(rel_path)

        if method == 'OPTIONS':
            if rel_path.startswith('/panel/api/'):
                return self._proxy('OPTIONS', rel_path)
            self.send_response(204)
            self.end_headers()
            return

        if path in ('/sub/clash', '/sub/clash.yaml'):
            return self._handle_client_sub(method)

        if rel_path.startswith('/panel/api/client-sub'):
            return self._handle_client_sub_info(method, rel_path)

        if rel_path.startswith('/panel/api/subscriptions'):
            return self._handle_subscriptions(method, rel_path)

        if rel_path.startswith('/panel/api/diagnostics'):
            return self._handle_diagnostics(method, rel_path)

        if rel_path.startswith('/panel/api/rules/simulate') or rel_path.startswith('/panel/api/user-rules/simulate'):
            return self._handle_rules_simulate(method, rel_path)

        if rel_path.startswith('/panel/api/user-rules'):
            return self._handle_user_rules(method, rel_path)

        if rel_path.startswith('/panel/api/'):
            return self._proxy(method, rel_path)

        if method == 'GET':
            return self._static()
        if method == 'HEAD':
            return self._static(head_only=True)

        self.send_error(404)

    def do_CONNECT(self):
        self.send_error(405)

    def do_GET(self):
        if self.headers.get('Upgrade', '').lower() == 'websocket' and ('/api/' in self.path or self.path.endswith('/api')):
            return self._dispatch('GET', is_ws=True)
        return self._dispatch('GET')

    def do_HEAD(self):
        return self._dispatch('HEAD', is_head=True)

    def do_POST(self):
        return self._dispatch('POST')

    def do_PUT(self):
        return self._dispatch('PUT')

    def do_PATCH(self):
        return self._dispatch('PATCH')

    def do_OPTIONS(self):
        return self._dispatch('OPTIONS')

    def do_DELETE(self):
        return self._dispatch('DELETE')

    def _static(self, head_only=False):
        path = self.path.split('?', 1)[0]
        if path in ('', '/', '/panel', '/panel/'):
            rel = 'index.html'
        elif path.startswith('/panel/'):
            rel = path[len('/panel/'):]
        else:
            rel = path.lstrip('/')
        target = (ROOT / rel).resolve()
        try:
            target.relative_to(ROOT)
        except ValueError:
            self.send_error(404)
            return
        if target.is_dir():
            target /= 'index.html'
        if not target.is_file():
            self.send_error(404)
            return
        try:
            st = target.stat()
            cache_key = str(target)
            with _STATIC_CACHE_LOCK:
                cached = _STATIC_CACHE.get(cache_key)
                if cached and cached[0] == st.st_mtime_ns and cached[1] == st.st_size:
                    data = cached[2]
                else:
                    cached = None
            if cached is None:
                data = target.read_bytes()
                with _STATIC_CACHE_LOCK:
                    total = sum(len(v[2]) for v in _STATIC_CACHE.values())
                    if (len(_STATIC_CACHE) >= _STATIC_CACHE_MAX_ENTRIES
                            or total + len(data) > _STATIC_CACHE_MAX_BYTES):
                        _STATIC_CACHE.clear()
                    _STATIC_CACHE[cache_key] = (st.st_mtime_ns, st.st_size, data)
        except OSError:
            self.send_error(404)
            return
        if target.name == 'index.html':
            self.send_response(200)
            self.send_header('Content-Type', mimetypes.guess_type(str(target))[0] or 'application/octet-stream')
            self.send_header('Content-Length', str(len(data)))
            self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate')
            self.end_headers()
            if not head_only:
                self.wfile.write(data)
            return
        # The shipped assets are content-addressed (hashed filename or
        # ?v=<sha256> cache-buster). Without an explicit header, Cloudflare
        # edge-caches js/css for its default 4h TTL, so a just-deployed
        # bundle can keep being served stale for hours ("button disappeared"
        # class of bugs). Pin assets to revalidate-anytime: correct by
        # construction and cheap via ETag / If-None-Match.
        # ETag is a content hash (not mtime+size) so identical bytes revalidate
        # identically across the tebi/pxed NFS pair, and _etag_matches() below
        # tolerates weak (W/"...") / quoted / comma-list validators the way
        # browsers and intermediaries actually send them.
        digest = hashlib.sha256(data).hexdigest()
        etag = '"%s"' % digest
        inm = (self.headers.get('If-None-Match') or '').strip()
        if _etag_matches(inm, digest):
            self.send_response(304)
            self.send_header('ETag', etag)
            self.send_header('Cache-Control', 'private, no-cache, must-revalidate')
            self.send_header('Content-Length', '0')
            self.end_headers()
            return
        self.send_response(200)
        self.send_header('Content-Type', mimetypes.guess_type(str(target))[0] or 'application/octet-stream')
        self.send_header('Content-Length', str(len(data)))
        self.send_header('ETag', etag)
        self.send_header('Cache-Control', 'private, no-cache, must-revalidate')
        self.end_headers()
        if not head_only:
            self.wfile.write(data)

    def log_message(self, fmt, *args):
        print('%s %s' % (self.address_string(), fmt % args), flush=True)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True

    def handle_error(self, request, client_address):
        exc = __import__('sys').exc_info()[1]
        if isinstance(exc, (ConnectionResetError, BrokenPipeError)):
            return
        super().handle_error(request, client_address)


if __name__ == '__main__':
    record_node_ip()
    _startup_diagnostics()

    WARM_INTERVAL = 10
    WARM_ENDPOINTS = ['/version', '/proxies', '/rules', '/configs']

    def _warm_loop():
        # Only warm this host's OWN local mihomo (/panel/api). Each gateway keeps
        # its own local cache warm; we deliberately do NOT poll the remote node
        # over the slow VPC (e.g. tebi poking pxed). That remote polling was
        # redundant (pxed warms itself) and, when pxed was overloaded, spammed
        # 502s into the other host's gateway log -- exactly the "pxed error on
        # tebi" the user saw. Local-only warming keeps every node fast and quiet.
        token = panel_password()
        while True:
            for ep in WARM_ENDPOINTS:
                try:
                    conn = http.client.HTTPConnection('127.0.0.1', 2053, timeout=15)
                    conn.request('GET', '/panel/api' + ep, headers={
                        'Authorization': 'Bearer ' + token,
                        REFRESH_HEADER: '1',
                    })
                    resp = conn.getresponse()
                    resp.read()
                    conn.close()
                except Exception:
                    try:
                        conn.close()
                    except Exception:
                        pass
            time.sleep(WARM_INTERVAL)

    threading.Thread(target=_warm_loop, daemon=True).start()

    Server(('0.0.0.0', 2053), Handler).serve_forever()
