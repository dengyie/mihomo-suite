#!/opt/mamba/bin/python3
"""胡桃美国出口桥自检/自愈 (Xray 默认出口依赖 10818 listener)

背景: Xray 无 anytls, 默认出口靠 mihomo listener 10818 转发到胡桃美国节点。
mihomo 对 listeners[].proxy 悬空引用不报错 (端口开着但转发不通), 故需外部自检。

用法:
  hutao-bridge-guard.py            # 自检 + 必要时自愈 + reload
  hutao-bridge-guard.py --check    # 只自检, 不写盘不 reload (退出码表状态)
  hutao-bridge-guard.py --watch N  # 每 N 秒循环自检自愈 (前台常驻)

退出码: 0 健康(或已自愈)  1 桥不可用(已探测无可用节点/组出口失败)  2 配置异常
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path

import yaml

CLASH_DIR = Path("/personal/clash")
CFG = CLASH_DIR / "config.yaml"
MERGED = CLASH_DIR / "config.mac-merged.yaml"
SECRET_FILE = CLASH_DIR / ".controller-secret"
LOG = CLASH_DIR / "hutao-bridge-guard.log"
API = "http://127.0.0.1:9090"

LISTENER_NAME = "hutao-us-xray-default"
BRIDGE_PORT = 10818
# 胡桃美国出口候选, 按优先级; D 为历史默认
# 胡桃美国出口候选, 按优先级 (2026-11-02)。原 美国_BGP_* 系列为草莓机场节点,
# 域名已撤服(api/lb.download.strawberrymemo.com 均无 A/AAAA), 全部不可达;
# 换为经 delay 实测的优质美国出口: BK-美国原生 洛杉矶 linode 最快,
# TUIC/AnyTLS-googlevps 为自建 Google VPS 最稳兜底。
CANDIDATES = (
    # 2026-11-02: 优先用 fallback 组, 让 tebi/pxed 各自选本机可达的美国成员
    # (pxed 侧 BK-美国01 不可达, 单节点写法会把 pxed 10818 打成 502)。
    "hutao-us-fallback",
    "BK-🇺🇸【北美洲】美国03原生丨直连【2x】",
    "BK-🇺🇸【北美洲】美国04原生丨直连【2x】",
    "BK-🇺🇸【北美洲】美国01原生丨直连【2x】",
    "TUIC-googlevps",
    "AnyTLS-googlevps",
    "[自建] 🇺🇸TUIC-googlevps",
    "[自建] 🇺🇸AnyTLS-googlevps",
    "🇺🇸【北美洲】美国03原生丨直连【2x】",
    "🇺🇸【北美洲】美国01原生丨直连【2x】",
    "[tomorin] US LAS Buyvm",
    "[share] 🇺🇸US-Vmess1(Bwh)",
)
PROBE_URL = "http://www.gstatic.com/generate_204"
PROBE_TIMEOUT_MS = 5000
# 落盘前的完整性下限, 防止把 config 写残 (曾发生)
MIN_PROXIES = 70
MIN_RULES = 1000


def log(msg: str) -> None:
    line = f"{datetime.now().strftime('%F %T')} {msg}"
    print(line, flush=True)
    try:
        with LOG.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except OSError:
        pass


def secret() -> str:
    if SECRET_FILE.is_file():
        return SECRET_FILE.read_text(encoding="utf-8").strip()
    data = yaml.safe_load(CFG.read_text(encoding="utf-8"))
    return str(data.get("secret") or "")


def api(path: str, method: str = "GET", body: bytes | None = None, timeout: int = 20):
    req = urllib.request.Request(
        API + path,
        data=body,
        method=method,
        headers={"Authorization": "Bearer " + secret(), "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read()
        return resp.status, (json.loads(raw) if raw else None)


def node_delay(name: str) -> int | None:
    """经 controller 测该节点延迟; None 表示不通。"""
    q = urllib.parse.quote(name, safe="")
    path = f"/proxies/{q}/delay?timeout={PROBE_TIMEOUT_MS}&url={urllib.parse.quote(PROBE_URL, safe='')}"
    for attempt in (1, 2):
        try:
            _, obj = api(path, timeout=PROBE_TIMEOUT_MS // 1000 + 5)
            if obj and "delay" in obj:
                return int(obj["delay"])
        except Exception:
            pass
        if attempt == 1:
            time.sleep(2)
    return None


def bridge_egress_ok(attempts: int = 1, gap: float = 3.0) -> bool:
    """真实过一遍 10818, 确认不是"端口开着但转发不通"。

    attempts>1 用于冷启动: mihomo 刚起时 provider 还没加载完, 单次探测会假阴性,
    曾导致 keeper 拉起 mihomo 后 guard 误判"全部节点不可达"。
    """
    for i in range(max(1, attempts)):
        r = subprocess.run(
            ["curl", "-qsS", "-o", "/dev/null", "-w", "%{http_code}",
             "-x", f"http://127.0.0.1:{BRIDGE_PORT}", "--max-time", "12", PROBE_URL],
            capture_output=True, text=True,
        )
        if r.stdout.strip() == "204":
            return True
        if i + 1 < max(1, attempts):
            time.sleep(gap)
    return False


def load(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def header_of(path: Path) -> str:
    """保留文件顶部注释块 (health-filter / hutao inject 记录)。"""
    buf = []
    for ln in path.read_text(encoding="utf-8").splitlines(keepends=True):
        if ln.startswith("#") or not ln.strip():
            buf.append(ln)
            if len(buf) > 40:
                break
        else:
            break
    return "".join(buf)


class NoAliasDumper(yaml.SafeDumper):
    def ignore_aliases(self, data):  # noqa: ANN001, ANN201
        return True


def write_listener(target: str) -> None:
    """把 listeners[].proxy 指到 target, 写 mac-merged(源) + config.yaml。

    只改 listeners 一个键, 其余原样 round-trip, 落盘前做完整性自检。
    """
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    listener = {
        "name": LISTENER_NAME,
        "type": "mixed",
        "port": BRIDGE_PORT,
        "listen": "127.0.0.1",
        "proxy": target,
    }
    for path in (MERGED, CFG):
        if not path.is_file():
            continue
        original = path.read_text(encoding="utf-8")
        data = yaml.safe_load(original)
        others = [l for l in (data.get("listeners") or []) if l.get("name") != LISTENER_NAME]
        data["listeners"] = others + [listener]

        body = yaml.dump(data, Dumper=NoAliasDumper, allow_unicode=True,
                         sort_keys=False, width=120, default_flow_style=False)
        check = yaml.safe_load(body)
        n_px, n_rules = len(check.get("proxies") or []), len(check.get("rules") or [])
        if n_px < MIN_PROXIES or n_rules < MIN_RULES:
            raise SystemExit(f"ABORT sanity: {path.name} proxies={n_px} rules={n_rules}")
        if not check.get("mixed-port"):
            raise SystemExit(f"ABORT sanity: {path.name} lost mixed-port")

        path.with_suffix(path.suffix + f".pre-guard-{ts}").write_text(original, encoding="utf-8")
        path.write_text(header_of(path) + body, encoding="utf-8")
        log(f"  wrote {path.name} listener.proxy={target} (bak .pre-guard-{ts})")


def reload_from_disk() -> bool:
    try:
        status, _ = api("/configs?force=true", "PUT",
                        json.dumps({"path": str(CFG)}).encode(), timeout=90)
        return status in (200, 204)
    except Exception as exc:  # noqa: BLE001
        log(f"  reload failed: {exc}")
        return False


def wait_port(port: int, timeout: float = 15.0) -> bool:
    import socket
    deadline = time.time() + timeout
    while time.time() < deadline:
        s = socket.socket()
        s.settimeout(0.5)
        ok = s.connect_ex(("127.0.0.1", port)) == 0
        s.close()
        if ok:
            return True
        time.sleep(0.5)
    return False


def pick_healthy(proxies: set[str], exclude: str | None = None) -> str | None:
    for name in CANDIDATES:
        if name == exclude or name not in proxies:
            continue
        d = node_delay(name)
        if d is not None:
            log(f"  candidate {name} delay={d}ms OK")
            return name
        log(f"  candidate {name} unreachable")
    return None


def group_members(data: dict, name: str) -> list[str]:
    for g in data.get("proxy-groups") or []:
        if isinstance(g, dict) and g.get("name") == name:
            return [str(m) for m in (g.get("proxies") or [])]
    return []


def run_once(check_only: bool) -> int:
    data = load(CFG)
    node_names = {str(p.get("name")) for p in (data.get("proxies") or [])}
    group_names = {str(g.get("name")) for g in (data.get("proxy-groups") or []) if g.get("name")}
    # listener.proxy 的合法目标既可以是节点, 也可以是组; 否则组名会被误判为悬空引用。
    proxies = node_names | group_names
    listeners = data.get("listeners") or []
    mine = next((l for l in listeners if l.get("name") == LISTENER_NAME), None)

    if mine is None:
        log(f"MISSING listener {LISTENER_NAME} in {CFG.name}")
        if check_only:
            return 2
        target = pick_healthy(proxies)
        if not target:
            log("FAIL no healthy 胡桃美国 node; refuse to write")
            return 1
        write_listener(target)
        reload_from_disk()
        wait_port(BRIDGE_PORT)
        return 0 if bridge_egress_ok() else 1

    ref = str(mine.get("proxy") or "")
    is_group = ref in group_names
    dangling = ref not in proxies
    if dangling:
        log(f"DANGLING listener.proxy={ref!r} not in proxies "
            f"({len(node_names)} nodes / {len(group_names)} groups)")
    else:
        log(f"listener.proxy={ref} present in proxies")

    port_up = wait_port(BRIDGE_PORT, timeout=10)
    # 悬空引用是配置事实, 立刻处理; 转发不通则多探几次再判, 避开冷启动假阴性。
    egress = bridge_egress_ok(attempts=1 if dangling else 3) if port_up else False
    log(f"bridge port={port_up} egress204={egress}")

    if not dangling and egress:
        return 0

    # --check 契约: 只报告状态, 0=健康 / 2=桥不可用(不写盘)。
    # 1 留给"已探测确认无可用节点", 由自愈分支返回。
    if check_only:
        return 2

    # 组形态: config.yaml 由 tebi/pxed 共享 NFS. 改成单节点会让对端失配
    # (pxed 对部分 BK 节点不可达 -> 502, 即 2026-11-02 修复前的故障),
    # 所以这里只诊断、不改写。组自身按 interval 重选; 整池都挂时也没有可换的节点。
    if is_group:
        members = [m for m in group_members(data, ref) if m in node_names]
        reachable = [m for m in members if node_delay(m) is not None]
        if reachable:
            log(f"group {ref} egress failing but {len(reachable)}/{len(members)} member(s) "
                f"delay-OK; fallback re-picks by itself, leaving config untouched")
        else:
            log(f"FAIL group {ref} egress failing and 0/{len(members)} member(s) reachable; "
                f"pool dead, no single-node rewrite (shared config would break peer)")
        return 1

    # 单节点形态: 悬空引用 或 端口在但转发不通 -> 换一个能通的美国节点
    target = pick_healthy(proxies, exclude=ref)
    if not target:
        # 所有候选都探不到 != 真的都挂了。先确认桥是不是其实已经通了。
        if not dangling and bridge_egress_ok(attempts=2):
            log("probe flapped but bridge is actually OK; leaving config untouched")
            return 0
        log("FAIL no healthy 胡桃美国 node; leaving config untouched")
        return 1
    if target != ref or dangling:
        write_listener(target)
    if not reload_from_disk():
        return 1
    wait_port(BRIDGE_PORT)
    ok = bridge_egress_ok()
    log(f"HEALED listener.proxy={target} egress204={ok}")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true", help="只自检, 不写盘不 reload")
    ap.add_argument("--watch", type=int, default=0, metavar="SEC", help="每 SEC 秒循环自检自愈")
    args = ap.parse_args()

    if args.watch:
        log(f"=== guard watch every {args.watch}s ===")
        while True:
            try:
                run_once(check_only=False)
            except SystemExit as exc:
                log(f"guard aborted: {exc}")
            except Exception as exc:  # noqa: BLE001
                log(f"guard error: {exc!r}")
            time.sleep(args.watch)
    return run_once(check_only=args.check)


if __name__ == "__main__":
    sys.exit(main())
