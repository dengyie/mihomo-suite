#!/usr/bin/env python3
"""Decisive tiebreak for flapping nodes: 10s timeout, 6 rounds, 2 urls."""
import json, socket, urllib.parse, http.client, concurrent.futures

SOCK = "/var/run/clash-verge-service/users/501/verge-mihomo.sock"
CANDIDATES = [
    "AnyTLS-googlevps",
    "[tomorin] [anytls]VN Hanoi VNPT",
    "[tomorin] [anytls]VN Hanoi VNPT IPv6",
    "[tomorin] US LAS Buyvm",
    "[tomorin] US LAS Buyvm IPv6",
    "[tomorin] [anytls]CH BRN Buyvm AnyTLS",
    "[tomorin] [anytls]JP Osaka Oracle",
    "[share] 🇭🇰HK-Warp1(Sak)",
]
URLS = ["http://www.gstatic.com/generate_204", "http://cp.cloudflare.com/generate_204"]


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
        return json.loads(body).get("delay")
    except Exception:
        return None


def test(name):
    hits, vals = 0, []
    for _ in range(6):
        for url in URLS:
            d = delay(name, url, 10000)
            if d is not None:
                hits += 1
                vals.append(d)
    return name, hits, (min(vals) if vals else None)


with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
    for name, hits, best in ex.map(test, CANDIDATES):
        verdict = "KEEP" if hits >= 3 else "EXCLUDE"
        print(f"{verdict:<8} hits={hits}/12 best={best}  {name}")