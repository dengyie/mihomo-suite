<div align="center">

# MihomoSuite

**Automated Ops Gateway & Intelligent Routing Diagnostic Suite for Mihomo (Clash Meta)**

[![License](https://img.shields.io/badge/license-MIT-green.svg?style=flat-square)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.9+-3776AB.svg?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![Mihomo](https://img.shields.io/badge/Engine-Mihomo%20Meta-E58325.svg?style=flat-square)](https://github.com/MetaCubeX/mihomo)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg?style=flat-square&logo=docker&logoColor=white)](docker-compose.yml)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg?style=flat-square)]()

[English](./README.md) · [简体中文](./README.zh-CN.md) · [Core Features](#core-features) · [Architecture](#system-architecture) · [Quick Start](#quick-start) · [API Specification](#rest-api-specification)

</div>

---

## Architecture & Motivation

Traditional proxy dashboards (such as Yacd and Zashboard) focus primarily on manual node toggling and simple delay testing. In long-running, unattended production environments on soft routers, NAS appliances, or VPS instances, proxy operations encounter recurring reliability hurdles:

| Operational Challenge | Manual / External Tooling | MihomoSuite Solution |
| :--- | :--- | :--- |
| **Multi-Subscription Merging** | Relies on third-party online converters with token leak hazards | **Local Private Aggregation**: Inter-process file locking (`fcntl`), multi-protocol parsing, and regex sanitization |
| **Configuration Regression Risks** | Malformed YAML syntax or typos crash the core daemon | **Preflight Testing & Atomic Rollback**: Preflights via `mihomo -t` before disk writes with automatic snapshot recovery |
| **Silent Routing & DNS Poisoning** | Connectivity is guessed blindly while sensitive AI sites are poisoned | **Simulation Engine**: Emulates kernel routing tiers and actively identifies domestic DNS poisoning on AI services |
| **Egress Identity Visibility** | Single ping sources provide inaccurate geographic metadata | **Concurrent Multi-Source Racing**: Millisecond racing across global IP observers with real-time ISP and ASN telemetry |
| **Disruptive Configuration Reloads** | Process restarts sever active SSH, download, and game sockets | **Smooth Reload Guardian (Keeper)**: Hash-based idempotent sync dispatching native zero-downtime controller reloads |

---

## Core Features

### 1. Subscription & Node Lifecycle Engine (`subscription-manager.py`)
- **Multi-Protocol Adaptation**:
  - Automatically identifies and parses native Clash YAML files and Base64 subscription blobs.
  - Supports single and batch node URIs: Shadowsocks (`ss://`) with SIP002/Plugin extensions, VMess (`vmess://`), VLESS (`vless://`), Trojan (`trojan://`), and Hysteria2 (`hysteria2://` / `hy2://`).
  - Fault-tolerant Base64 decoding handling URL-safe variants and missing padding.
- **Node Hygiene & Ad Cleaning**:
  - Regular expression filters exclude promotional notices, remaining quotas, and customer service mock nodes.
  - Granular per-subscription exclusion regex configuration.
- **Namespace Isolation**:
  - Prefixes node identifiers with `[{Subscription Name}] {Original Name}` to prevent cross-provider naming collisions.
- **Atomic Aggregation & Metadata Storage**:
  - State, modification timestamps, and counts persist in `subscriptions/meta.json`.
  - Raw payloads are cached under `subscriptions/raw/` for audit trails and offline disaster recovery.
  - Output is committed atomically via `fcntl.flock` locks to `airports/airport-merged-sub.yaml`.
- **Web Subscription Center**:
  - Integrated modal supporting subscription additions, toggle states, on-demand refresh, and RAW node importing.

### 2. Multi-Source Egress Diagnostics (`gateway.py`)
- **Concurrent Edge Racing**:
  - Probes authoritative IP verification backends (`ipinfo.io`, `cloudflare.com/cdn-cgi/trace`, `api.ipify.org`, `ip-api.com`) with strict 3.5s per-source bounds.
  - Tracks round-trip latency (RTT) per probe, surfacing the fastest response along with full comparative results.
- **Egress Telemetry**:
  - Identifies active public egress IP, ISO country codes, city, ISP operator, and ASN routing records.
  - Supports routed inspection through the Mihomo proxy stack (default port `7897`) or direct local network testing.
- **Interactive UI Badge**:
  - Persistent navbar badge displaying current egress IP, region, and probe latency with auto-refreshing popovers.

### 3. Routing Simulation & DNS Poisoning Detector (`rules-reconciler.py`)
- **Kernel-Accurate Emulation**:
  - Strictly follows Mihomo precedence hierarchy: `DOMAIN` -> `DOMAIN-SUFFIX` -> `DOMAIN-KEYWORD` -> `IP-CIDR / IP-CIDR6` -> `GEOSITE` -> `GEOIP` -> `MATCH` / `DEFAULT`.
  - Evaluates active runtime configurations, pinpointing matched rule types, payloads, target groups, and rule indices.
- **Nameserver Policy Traceback**:
  - Resolves upstream DNS server groups assigned to evaluated hostnames based on `dns.nameserver-policy`.
- **AI & Sensitive Service Guard**:
  - Built-in signatures for critical global services (OpenAI, Claude, Anthropic, ChatGPT, GitHub, Google, YouTube, Twitter/X, Telegram, Discord, HuggingFace).
  - Triggers automated DNS Pollution Risk Alerts if sensitive domains resolve via unencrypted domestic resolvers.
- **Web Simulation Bar & Offline CLI**:
  - Interactive rule search bar on `#/rules` with highlighted rule targeting and CLI evaluation via `python3 clash/rules-reconciler.py --simulate <domain/ip>`.

### 4. Custom Rule Manager
- Embedded drawer supporting `DOMAIN-SUFFIX`, `DOMAIN`, `DOMAIN-KEYWORD`, `IP-CIDR`, `IP-CIDR6`, `GEOSITE`, and `GEOIP`.
- Dynamic dropdown of active proxy groups with real-time syntax linting and XSS escaping.

### 5. Multi-Layer Fault Tolerance
- **Syntax Validation**: Runs `mihomo -t` against candidate configs prior to application.
- **Transaction Rollback**: Restores timestamped backups atomically upon failure.
- **Rule Boundary Protection**: Deleting custom rules leaves subscription-provided rules untouched.
- **Constant-Time Verification**: Uses length-checked constant-time comparison to protect against timing attacks.

### 6. Secure Gateway & Dual-Host Routing (`gateway.py`)
- Unified service delivering static assets, reverse proxy APIs, and WebSocket multiplexing.
- Injects `.controller-secret` server-side, eliminating browser token exposure.
- Intelligent cluster routing bridging macOS (`tebi`) and Linux (`pxed`) hosts transparently.
- Memory-cached NFS static asset delivery invalidated on file modification or size changes.

### 7. Keeper Daemon (`clash-keeper-loop.sh`)
- 120-second background verification loop.
- SHA-256 idempotency prevents duplicate writes, redundant backups, or unneeded service reloads.
- Dispatches zero-downtime hot reloads via `PUT /configs?force=true`.

---

## System Architecture

```text
       [ Airport A (YAML) ]     [ Airport B (Base64) ]     [ Custom Nodes (vless/hy2) ]
               │                          │                             │
               └──────────────────────────┼─────────────────────────────┘
                                          ▼
      ┌─────────────────────────────────────────────────────────────────┐
      │                          MihomoSuite                            │
      │                                                                 │
      │  ┌─────────────────────────────┐   ┌─────────────────────────┐  │
      │  │    subscription-manager     │   │    rules-reconciler     │  │
      │  │  · Cleaning & ad filtering  │   │  · Routing simulation   │  │
      │  │  · fcntl file locking       │   │  · DNS poison detector  │  │
      │  └──────────────┬──────────────┘   └────────────┬────────────┘  │
      │                 │                               │               │
      │                 ▼                               ▼               │
      │  ┌───────────────────────────────────────────────────────────┐  │
      │  │            Security Gateway & Diagnostics Engine          │  │
      │  │  · Constant-time auth isolation  · Multi-source IP racing │  │
      │  └──────────────────────────────┬────────────────────────────┘  │
      └─────────────────────────────────┼───────────────────────────────┘
                                        │ Syntax check (mihomo -t)
                                        │ Seamless reload (PUT /configs?force=true)
                                        ▼
                             ┌──────────────────────┐
                             │  Mihomo Core Daemon  │
                             └──────────────────────┘
```

---

## Directory Structure

```text
.
├── clash/
│   ├── rules-reconciler.py         # Rules engine, verification, rollback, and simulation
│   ├── subscription-manager.py     # Multi-protocol parser, ad cleaning, and atomic output
│   ├── apply-local-import.py       # Local node injection script
│   └── clash-keeper-loop.sh        # Keeper background daemon (120s self-check loop)
├── zashboard/
│   ├── gateway.py                  # API gateway, reverse proxy, WS, and multi-source probe
│   ├── start-gateway.sh            # Gateway startup wrapper
│   ├── src/
│   │   └── user-rules-ui.js        # Frontend extension source components
│   └── dist/                       # Compiled dashboard production assets
│       ├── assets/
│       │   └── user-rules-ui.js    # Built frontend bundle
│       └── index.html              # Dashboard single-page entry
├── tests/
│   ├── test_auth.py                # Constant-time authentication tests
│   ├── test_cache.py               # Static caching regression tests
│   ├── test_gateway_endpoints.py   # Gateway HTTP endpoint test suite
│   ├── test_reconciler_load.py     # Hot reload and script mtime monitoring tests
│   ├── test_rule_simulation.py     # Routing and DNS pollution evaluation tests
│   ├── test_subscription_manager.py # Subscription parsing and aggregation tests
│   └── test_ui_bundle.mjs          # Headless DOM and UI interaction tests
├── Dockerfile                      # Production container image manifest
├── docker-compose.yml              # Container orchestration configuration
├── requirements.txt                # Python runtime dependencies
└── package.json                    # Frontend build and testing scripts
```

---

## Quick Start

### Prerequisites
- Python 3.9 or higher
- Running instance of [Mihomo (Clash Meta)](https://github.com/MetaCubeX/mihomo) with External Controller enabled
- Linux or macOS environment

### Local Setup
```bash
# 1. Clone repository
git clone https://github.com/dengyie/mihomo-suite.git
cd mihomo-suite

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Initialize credentials
touch zashboard/panel.password      # Enter your web panel password
touch clash/.controller-secret     # Enter your Mihomo External Controller Secret

# 4. Start gateway
chmod +x zashboard/start-gateway.sh clash/clash-keeper-loop.sh
./zashboard/start-gateway.sh
```

Access the dashboard at `http://127.0.0.1:2053/panel/`.

---

## Docker Deployment

```bash
# Start container in detached mode
docker compose up -d

# Inspect execution logs
docker compose logs -f
```

---

## REST API Specification

All `/panel/api/*` endpoints require the `Authorization: Bearer <PANEL_PASSWORD>` header:

| Method | Endpoint | Description | Sample Query / Body |
| :--- | :--- | :--- | :--- |
| `GET` | `/panel/api/subscriptions` | Retrieve subscription list and metadata | None |
| `POST` | `/panel/api/subscriptions` | Add subscription endpoint | `{"name":"Sub1","url":"https://...","exclude_filter":""}` |
| `POST` | `/panel/api/subscriptions/import-nodes` | Bulk import raw nodes | `{"name":"Manual","text":"ss://...","skip_merge":true}` |
| `POST` | `/panel/api/subscriptions/<sub_id>/update` | Update or refresh subscription | `{"name":"Sub1","refresh":true}` |
| `POST` | `/panel/api/subscriptions/<sub_id>/toggle` | Enable or disable subscription | `{"enabled": true}` |
| `DELETE` | `/panel/api/subscriptions/<sub_id>` | Remove subscription and re-aggregate | None |
| `GET` | `/panel/api/diagnostics/egress-ip` | Multi-source egress IP probe | `?proxy=true&proxy_port=7897` |
| `POST` | `/panel/api/rules/simulate` | Execute routing simulation | `{"domain": "api.openai.com"}` |
| `GET` | `/panel/api/user-rules` | Fetch user custom rule sets | None |
| `POST` | `/panel/api/user-rules` | Add custom rule and hot-reload | `{"type":"DOMAIN-SUFFIX","payload":"anthropic.com","target":"PROXY"}` |
| `DELETE` | `/panel/api/user-rules/<rule_id>` | Delete custom rule and hot-reload | None |
| `GET` | `/panel/api/user-rules/targets` | List available proxy group targets | None |

---

## Command Line Interface (CLI)

### Subscription Manager (`subscription-manager.py`)
```bash
# List configured subscriptions and node counts
python3 clash/subscription-manager.py --list

# Register remote subscription
python3 clash/subscription-manager.py --add "ProviderA" "https://example.com/api/v1/client/subscribe?token=xxx"

# Import nodes from raw URI string
python3 clash/subscription-manager.py --import-nodes "BackupNodes" "ss://YWVzLTI1Ni1nY206cGFzc0AxMi4zNC41Ni43ODo4Mzg4#HK-Node1"

# Force pull and re-aggregate configurations
python3 clash/subscription-manager.py --reconcile --fetch

# Delete subscription
python3 clash/subscription-manager.py --delete "sub_xxxxxx"
```

### Rules Reconciler & Simulator (`rules-reconciler.py`)
```bash
# Emulate routing policy and evaluate DNS pollution risk
python3 clash/rules-reconciler.py --simulate "api.openai.com"
python3 clash/rules-reconciler.py --simulate "114.114.114.114"

# Perform dry run syntax check
python3 clash/rules-reconciler.py --dry-run

# Reconcile rules and dispatch controller reload
python3 clash/rules-reconciler.py --reconcile
```

---

## Automated Testing & Quality Assurance

```bash
# Run full suite (UI interaction + Python test suites)
npm test

# Run Python unit tests directly
python3 -m pytest tests/

# Run headless UI bundle tests
node tests/test_ui_bundle.mjs
```

---

## Security & Isolation Policies

- **Credential Separation**: `panel.password` and `.controller-secret` are gitignored. The server injects the controller secret internally without frontend exposure.
- **SSRF Hardening**: Subscriptions accept only `http`/`https` schemas and reject private, loopback (`127.0.0.1`), link-local, and cloud metadata IPs without following cross-host redirects. Payload bodies are capped at 8 MiB.
- **Reverse Proxy Whitelist**: `/panel/api` forwards only required Mihomo endpoints; `/delay?url=` allows only standard diagnostic endpoints (`generate_204`, Cloudflare trace).
- **Filesystem Boundaries**: Configuration paths are confined within `CLASH_ROOT`. Dead node cleanup applies only to `airports/local-nodes.yaml` without mutating root configs.

---

## License

Released under the [MIT License](LICENSE).
