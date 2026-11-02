#!/usr/bin/env python3
"""Confirm 3x-ui dead node list through running mihomo core, output JSON.

Two tiers: quick pass (5s x 2 urls x 2 rounds); failures get a slow
re-verification (8s x 2 urls x 2 rounds) so genuinely slow nodes are not
misclassified as dead.
"""
import json, socket, sys, urllib.parse, concurrent.futures, http.client
from collections import defaultdict

SOCK = "/var/run/clash-verge-service/users/501/verge-mihomo.sock"
SUB = sys.argv[1] if len(sys.argv) > 1 else "/tmp/dl-3xui/sub.yaml"
OUT = sys.argv[2] if len(sys.argv) > 2 else "/tmp/scripts/results.json"

import yaml
conf = yaml.safe_load(open(SUB))
nodes = [p["name"] for p in conf.get("proxies", []) if p.get("server") and p.get("port")]


class Conn(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(SOCK)


def delay(name, url, timeout_ms):
    q = urllib.parse.quote(name, safe="")
    u = urllib.parse.quote(url, safe="")
    try:
        c = Conn("localhost", timeout=timeout_ms / 1000 + 5)
        c.request("GET", f"/proxies/{q}/delay?timeout={timeout_ms}&url={u}")
        r = c.getresponse()
        body = r.read().decode()
        c.close()
        d = json.loads(body)
        return d.get("delay")
    except Exception:
        return None


URLS = [
    "http://www.gstatic.com/generate_204",
    "http://cp.cloudflare.com/generate_204",
]


def probe(name, timeout_ms):
    for _ in range(2):
        for url in URLS:
            if delay(name, url, timeout_ms) is not None:
                return True
    return False


def test(name):
    if probe(name, 5000):
        return name, "alive"
    if probe(name, 8000):
        return name, "slow"
    return name, "dead"


results = []
with concurrent.futures.ThreadPoolExecutor(max_workers=24) as ex:
    for r in ex.map(test, nodes):
        results.append(r)

alive = sorted(n for n, s in results if s == "alive")
slow = sorted(n for n, s in results if s == "slow")
dead = sorted(n for n, s in results if s == "dead")

json.dump({"alive": alive, "slow": slow, "dead": dead}, open(OUT, "w"), ensure_ascii=False, indent=1)

print(f"nodes={len(nodes)} alive={len(alive)} slow={len(slow)} dead={len(dead)}")
print("\n-- slow (kept, not excluded) --")
for n in slow:
    print("  ", n)
print("\n-- dead (to exclude) --")
for n in dead:
    print("  ", n)