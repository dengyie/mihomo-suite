#!/usr/bin/env python3
"""Probe mihomo leaf proxies via controller delay API; filter dead from GROK groups.

Usage (on pxed):
  python3 probe_clash_nodes.py                 # probe + report + rewrite groups
  python3 probe_clash_nodes.py --dry-run       # probe only
  python3 probe_clash_nodes.py --apply-config  # also rewrite config.mac-merged.yaml

Default test URL: http://www.gstatic.com/generate_204
Timeout per node: 5000ms (controller delay timeout)
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

CLASH_DIR = Path("/personal/clash")
CFG = CLASH_DIR / "config.yaml"
MERGED = CLASH_DIR / "config.mac-merged.yaml"
SECRET_FILE = CLASH_DIR / ".controller-secret"
API = "http://127.0.0.1:9090"
REPORT_DIR = Path("/personal/grok-register/output")
DEFAULT_URL = "http://www.gstatic.com/generate_204"
DEFAULT_TIMEOUT_MS = 5000
GROUP_TYPES = {
    "Selector",
    "URLTest",
    "Fallback",
    "LoadBalance",
    "Relay",
    "Direct",
    "Reject",
    "Compatible",
    "Pass",
    "PassRule",
    "RejectDrop",
}
# Groups whose leaf lists we rewrite to healthy-only for register batches
REGISTER_GROUPS = ("🎯Grok注册", "♻️Grok优选", "PROXY", "🔰ChatGPT")
# Always keep at front if healthy
SELF_TAG = "[自建] "


FLAG_RE = re.compile("^[\U0001F1E6-\U0001F1FF]{2}")


def bare_name(name: str) -> str:
    # 2026-11-03: pool names may carry a leading region flag after the tag.
    # Only self-built names are stripped: airport names may start with a flag of
    # their own ("🇸🇬【亚洲】新加坡03丨直连") and that flag is part of the name.
    if not name.startswith(SELF_TAG):
        return name
    return FLAG_RE.sub("", name[len(SELF_TAG):])


# Canonical bare names of the GCP/loopback nodes preferred for register batches;
# matched against bare_name() of live nodes (so "[自建] 🇺🇸TUIC-googlevps" matches
# "TUIC-googlevps"). Keep in sync with the pool after any self-built rename.
PREFERRED = (
    "TUIC-googlevps",
    "AnyTLS-googlevps",
    "VLESS-CF-DLD",
)


def load_secret() -> str:
    text = CFG.read_text(encoding="utf-8")
    m = re.search(r'^secret:\s*["\']?([^"\'\n]+)', text, re.M)
    if m:
        return m.group(1).strip()
    if SECRET_FILE.is_file():
        return SECRET_FILE.read_text(encoding="utf-8").strip()
    return "lRF7OjYAkoy41nj3jRzy4Zgu"


def api_request(path: str, secret: str, method: str = "GET", data: bytes | None = None) -> Any:
    req = urllib.request.Request(
        f"{API}{path}",
        data=data,
        method=method,
        headers={
            "Authorization": f"Bearer {secret}",
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(req, timeout=180) as resp:
        body = resp.read()
        if not body:
            return None
        return json.loads(body.decode())


def list_leaves(secret: str) -> list[str]:
    data = api_request("/proxies", secret)
    prox = data.get("proxies") or {}
    leaves: list[str] = []
    for name, info in prox.items():
        t = info.get("type") or ""
        if t in GROUP_TYPES:
            continue
        # skip built-ins
        if name in ("DIRECT", "REJECT", "PASS", "COMPATIBLE"):
            continue
        leaves.append(name)
    return sorted(leaves)


def probe_one(name: str, secret: str, timeout_ms: int, url: str) -> tuple[str, int | None, str]:
    q = urllib.parse.urlencode({"timeout": timeout_ms, "url": url})
    path = f"/proxies/{urllib.parse.quote(name, safe='')}/delay?{q}"
    try:
        data = api_request(path, secret)
        delay = data.get("delay") if isinstance(data, dict) else None
        if isinstance(delay, int) and delay > 0:
            return name, delay, "ok"
        return name, None, f"no_delay:{data!r}"
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode(errors="replace")
        except Exception:
            body = str(e)
        return name, None, f"http_{e.code}:{body[:120]}"
    except Exception as e:
        return name, None, f"{type(e).__name__}:{e}"


def probe_all(
    names: list[str],
    secret: str,
    timeout_ms: int,
    url: str,
    workers: int,
) -> dict[str, dict[str, Any]]:
    results: dict[str, dict[str, Any]] = {}
    total = len(names)
    done = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {
            ex.submit(probe_one, n, secret, timeout_ms, url): n for n in names
        }
        for fut in concurrent.futures.as_completed(futs):
            name, delay, status = fut.result()
            results[name] = {"delay_ms": delay, "status": status, "ok": delay is not None}
            done += 1
            if done % 10 == 0 or done == total:
                ok_n = sum(1 for v in results.values() if v["ok"])
                print(f"  progress {done}/{total} ok={ok_n}", flush=True)
    return results


def classify(name: str) -> str:
    name = bare_name(name)
    if name.startswith("IK-"):
        return "ikuuu"
    if name.startswith("BK-"):
        return "pokemon"
    if name.startswith("GVPS-"):
        return "gvps"
    return "other"


def put_group_now(secret: str, group: str, node: str) -> None:
    path = f"/proxies/{urllib.parse.quote(group, safe='')}"
    body = json.dumps({"name": node}).encode()
    try:
        api_request(path, secret, method="PUT", data=body)
        print(f"  set {group} -> {node}")
    except Exception as e:
        print(f"  WARN set {group}: {e}")


def rewrite_config_groups(
    cfg_path: Path,
    healthy: list[str],
    preferred_first: list[str],
) -> Path:
    """Rewrite proxy-groups leaf lists for register-related groups; backup first."""
    try:
        import yaml  # type: ignore
    except ImportError:
        # system may lack pyyaml — use regex-free path via local venv if present
        for cand in (
            Path("/personal/grok-register/.venv/bin/python"),
            Path("/personal/clash/.venv/bin/python"),
        ):
            if cand.is_file():
                # re-exec note: caller should use venv; here fail clearly
                pass
        raise SystemExit("PyYAML required on host to --apply-config (use grok-register venv)")

    text = cfg_path.read_text(encoding="utf-8")
    data = yaml.safe_load(text)

    ordered = list(preferred_first) + [n for n in healthy if n not in preferred_first]

    groups = data.get("proxy-groups") or []
    for g in groups:
        name = g.get("name")
        if name not in REGISTER_GROUPS:
            continue
        old = list(g.get("proxies") or [])
        # rebuild: preferred healthy + remaining healthy + DIRECT for select
        if g.get("type") == "url-test":
            g["proxies"] = ordered[:] if ordered else old
        else:
            new = ordered[:]
            for m in ("♻️Grok优选", "DIRECT"):
                if m not in new and m in old:
                    new.append(m)
            g["proxies"] = new if new else ["DIRECT"]
        print(f"  group {name}: {len(old)} -> {len(g['proxies'])}")

    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    bak = cfg_path.with_suffix(cfg_path.suffix + f".pre-health-{ts}")
    bak.write_text(text, encoding="utf-8")
    # 只保留最近 RETAIN 份同族备份, 否则每轮两份会无界增长(曾累积 1300+ 份 / 500MB)
    RETAIN = 20
    try:
        fam = sorted(cfg_path.parent.glob(cfg_path.name + ".pre-health-*"))
        for stale in fam[:-RETAIN]:
            stale.unlink()
    except OSError:
        pass
    class NoAliasDumper(yaml.SafeDumper):
        def ignore_aliases(self, data):  # type: ignore[no-untyped-def]
            return True

    header = ""
    if text.lstrip().startswith("#"):
        # keep first comment block lines
        lines = text.splitlines(keepends=True)
        buf = []
        for ln in lines:
            if ln.startswith("#") or ln.strip() == "":
                buf.append(ln)
                if len(buf) > 20:
                    break
            else:
                break
        header = "".join(buf)
        if header and not header.endswith("\n"):
            header += "\n"
        header += f"# health-filter {ts} healthy={len(healthy)} dead_stripped_from {','.join(REGISTER_GROUPS)}\n"

    body = yaml.dump(
        data,
        Dumper=NoAliasDumper,
        allow_unicode=True,
        sort_keys=False,
        width=120,
        default_flow_style=False,
    )
    cfg_path.write_text(header + body, encoding="utf-8")
    print(f"  wrote {cfg_path} (bak {bak.name})")
    return bak


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--url", default=DEFAULT_URL)
    ap.add_argument("--timeout-ms", type=int, default=DEFAULT_TIMEOUT_MS)
    ap.add_argument("--workers", type=int, default=12)
    ap.add_argument("--dry-run", action="store_true", help="probe only, no group select / config write")
    ap.add_argument(
        "--apply-config",
        action="store_true",
        help="rewrite config.yaml + config.mac-merged.yaml groups to healthy leaves and restart not auto",
    )
    ap.add_argument(
        "--select",
        default="",
        help="force 🎯Grok注册/PROXY selection to this node if healthy (default: first preferred healthy)",
    )
    ap.add_argument("--max-latency-ms", type=int, default=4500, help="treat delay above this as dead")
    args = ap.parse_args()

    secret = load_secret()
    print(f"secret_len={len(secret)} url={args.url} timeout_ms={args.timeout_ms}")
    leaves = list_leaves(secret)
    print(f"leaves={len(leaves)}")

    t0 = time.time()
    results = probe_all(leaves, secret, args.timeout_ms, args.url, args.workers)
    elapsed = time.time() - t0

    healthy: list[str] = []
    dead: list[str] = []
    for name in leaves:
        r = results[name]
        d = r["delay_ms"]
        if r["ok"] and isinstance(d, int) and d <= args.max_latency_ms:
            healthy.append(name)
        else:
            dead.append(name)

    # sort healthy by delay
    healthy.sort(key=lambda n: results[n]["delay_ms"] or 99999)
    preferred_first = [n for n in healthy if bare_name(n) in PREFERRED]

    by_cls_ok = Counter(classify(n) for n in healthy)
    by_cls_dead = Counter(classify(n) for n in dead)

    print("\n=== SUMMARY ===")
    print(f"elapsed_s={elapsed:.1f}")
    print(f"healthy={len(healthy)} dead={len(dead)}")
    print(f"healthy_by_class={dict(by_cls_ok)}")
    print(f"dead_by_class={dict(by_cls_dead)}")
    print("\n--- HEALTHY (delay ms) ---")
    for n in healthy:
        print(f"  OK  {results[n]['delay_ms']:>5}  {n}")
    print("\n--- DEAD / TIMEOUT ---")
    for n in dead:
        print(f"  DEAD {results[n]['status'][:80]}  {n}")

    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    report = {
        "ts": ts,
        "url": args.url,
        "timeout_ms": args.timeout_ms,
        "max_latency_ms": args.max_latency_ms,
        "healthy_count": len(healthy),
        "dead_count": len(dead),
        "healthy": [
            {"name": n, "delay_ms": results[n]["delay_ms"], "class": classify(n)}
            for n in healthy
        ],
        "dead": [
            {"name": n, "status": results[n]["status"], "class": classify(n)}
            for n in dead
        ],
        "preferred_first": preferred_first,
    }
    report_path = REPORT_DIR / f"clash_node_health_{ts}.json"
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    latest = REPORT_DIR / "clash_node_health_latest.json"
    latest.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    # plain list for PROXY_LIST / ops
    (REPORT_DIR / "clash_nodes_healthy.txt").write_text(
        "\n".join(healthy) + ("\n" if healthy else ""), encoding="utf-8"
    )
    (REPORT_DIR / "clash_nodes_dead.txt").write_text(
        "\n".join(dead) + ("\n" if dead else ""), encoding="utf-8"
    )
    print(f"\nreport={report_path}")

    if args.dry_run:
        print("dry-run: skip group select / config rewrite")
        return 0 if healthy else 2

    # Select best for register groups
    pick = args.select.strip()
    if pick and pick not in set(healthy):
        print(f"WARN requested --select {pick!r} not healthy; ignoring")
        pick = ""
    if not pick:
        pick = preferred_first[0] if preferred_first else (healthy[0] if healthy else "")
    if pick:
        for g in ("GLOBAL", "PROXY", "🎯Grok注册", "🔰ChatGPT"):
            put_group_now(secret, g, pick)
    else:
        print("ERROR: no healthy nodes — not changing selection")
        return 2

    if args.apply_config:
        print("\n=== rewrite config groups ===")
        for p in (CFG, MERGED):
            if p.is_file():
                rewrite_config_groups(p, healthy, preferred_first)
        print(
            "NOTE: restart mihomo to load rewritten groups:\n"
            "  bash /personal/grok-register/start-clash-for-grok.sh"
        )

    print(f"\nREADY for register batch: select={pick} healthy={len(healthy)}")
    return 0 if healthy else 2


if __name__ == "__main__":
    sys.exit(main())
