<div align="center">

# MihomoSuite

**专为 Mihomo (Clash Meta) 打造的企业级自动化运维网关与智能分流诊断套件**

[![License](https://img.shields.io/badge/license-MIT-green.svg?style=flat-square)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.9+-3776AB.svg?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![Mihomo](https://img.shields.io/badge/Engine-Mihomo%20Meta-E58325.svg?style=flat-square)](https://github.com/MetaCubeX/mihomo)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg?style=flat-square&logo=docker&logoColor=white)](docker-compose.yml)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg?style=flat-square)]()

[English](./README.md) · [简体中文](./README.zh-CN.md) · [核心特性](#核心特性) · [系统架构](#系统架构) · [快速上手](#快速上手) · [API 规范](#rest-api-接口规范) · [CLI 工具](#命令行工具实战-cli)

</div>

---

## 痛点与设计价值

传统前端面板（如 Yacd、Zashboard）的重心主要在节点手动切换与简单延时测速，但在多节点长期运行、无人值守的软路由、NAS 或 VPS 生产场景下，代理运维常面临一系列痛点：

| 运维痛点场景 | 传统手工 / 外部方案 | MihomoSuite 解决方案 |
| :--- | :--- | :--- |
| **多机场订阅整合** | 依赖第三方在线转换工具，节点配置与隐私 Token 存在泄露风险 | **本地私有化聚合**：跨进程文件排他锁 (`fcntl`)，多格式协议自适应，内置正则自动去广告清洗 |
| **配置变更易断网** | 修改 YAML 缩进错误或非法字符，内核崩溃退出导致全屋断网 | **事务预检与原子回滚**：写入前强制执行 `mihomo -t` 语法预检，失败自动恢复历史备份，零宕机 |
| **分流失灵与 DNS 污染** | 盲测连通性，ChatGPT/Claude/敏感站点常被国内 DNS 污染阻断 | **链路推演仿真引擎**：精准仿真内核匹配优先级，针对海外敏感及 AI 服务实施 DNS 污染主动研判与告警 |
| **真实出口节点感知** | 单一测速源延迟高、信息不准，无法确切得知落地节点的真实 ISP | **全球并发出口竞速**：多权威源毫秒级并发探测，Web 顶栏常驻展示真实出口 IP、ISP 与归属地 |
| **规则更新体验** | 重启客户端导致正在传输的下载进程、SSH、游戏等长连接瞬间断开 | **平滑热重载守护 (Keeper)**：基于配置 Hash 幂等合并，调用原生 `PUT /configs?force=true` 零感生效 |

---

## 核心特性

### 1. 订阅与节点全生命周期管理 (`subscription-manager.py`)
- **全协议多格式自适应解析**：
  - 自动识别并解析 Clash 原生 YAML 与 Base64 订阅源。
  - 支持单节点与批量节点 URI 解析，涵盖 Shadowsocks (`ss://`)（含 SIP002/Plugin 扩展）、VMess (`vmess://`)、VLESS (`vless://`)、Trojan (`trojan://`)、Hysteria2 (`hysteria2://` / `hy2://`)。
  - 健壮的 Base64 容错解码（自动处理 URL-Safe 字符与缺失填充符）。
- **垃圾节点清洗与广告过滤**：
  - 内置正则过滤器，自动剔除包含“剩余流量 / 官网 / 套餐 / 到期 / 公告 / 流量 / 重置 / 交流群 / 客服”等非代理展示性节点。
  - 支持按订阅自定义独立的排除正则规则。
- **命名空间前缀隔离**：
  - 自动为节点名注入 `[{订阅名称}] {节点原名}` 前缀，彻底规避跨机场订阅的节点重名冲突。
- **元数据跟踪与原子聚合**：
  - 订阅状态、更新时间、节点计数持久化存储于 `subscriptions/meta.json`。
  - 原始响应自动缓存于 `subscriptions/raw/` 目录，便于离线恢复与历史审计。
  - 基于 `fcntl.flock` 跨进程排他锁与临时文件原子重命名机制，聚合输出至 `airports/airport-merged-sub.yaml`。
- **Web UI 订阅管理中心**：
  - 规则页顶部一键唤起模态窗，支持一键添加订阅、启用/停用切换、手动刷新拉取、批量 RAW 节点粘贴导入与订阅删除。

### 2. 出口 IP 毫秒级多源竞速诊断 (`gateway.py`)
- **多数据源并发竞速探测**：
  - 并发探测全球权威 IP 识别节点（`ipinfo.io`、`cloudflare.com/cdn-cgi/trace`、`api.ipify.org`、`ip-api.com`），设置严格的 3.5s 单源超时控制。
  - 毫秒级统计各数据源 RTT 往返时延，动态甄选首位最快响应数据（`fastest`）并输出全量比对结果（`all_results`）。
- **多维度出口特征解析**：
  - 实时获取当前实际公网出口 IP、国家/地区代码、所属城市、ISP 运营商与 ASN 路由信息。
  - 支持指定代理端口（默认 `7897`）走 Mihomo 代理栈探测，或直连测试本地网络。
- **Web 导航栏悬浮 Badge 与交互式 Popover**：
  - 顶部导航栏常驻展示当前出口 IP、归属地与测速延迟，状态即时更新。
  - 点击弹出交互式信息卡，直观展示 ISP、ASN、地理位置与多源竞速延迟列表，并支持一键强制刷新探测。

### 3. 规则分流与 DNS 污染推演模拟器 (`rules-reconciler.py`)
- **真实分流链推演匹配**：
  - 严格依据 Mihomo 内核的分流匹配优先级与语义模拟推演：`DOMAIN` -> `DOMAIN-SUFFIX` -> `DOMAIN-KEYWORD` -> `IP-CIDR / IP-CIDR6` -> `GEOSITE` -> `GEOIP` -> `MATCH` / `DEFAULT`。
  - 自动加载当前生效配置，精确定位命中的规则类型、匹配载荷（Payload）、分流策略目标（Target）及规则索引行号。
- **DNS 解析策略 (Nameserver Policy) 回溯**：
  - 模拟当前激活配置中的 `dns.nameserver-policy` 规则（前缀通配 `+.`、通配符 `*.`、`geosite:`、特定域名），回溯推导该域名使用的上游 DNS 服务器组。
- **海外敏感服务 DNS 污染风险研判**：
  - 内置主流海外敏感及 AI 服务特征库（OpenAI、Claude、Anthropic、ChatGPT、GitHub、Google、YouTube、Twitter/X、Telegram、Netflix、Spotify、Discord、HuggingFace、Copilot 等）。
  - 实时监测：若敏感域名被国内未加密 DNS（如 `114.114.114.114`、`223.5.5.5` 等）解析，自动触发 DNS 污染风险告警，并提示配置安全分流。
- **Web 规则页嵌入式推演栏**：
  - 规则页（`#/rules`）顶部常驻单行推演输入栏，按回车或点击“推演”呈现匹配结果、目标策略组、DNS 服务器及风险告警。
- **CLI 离线推演支持**：
  - 支持通过终端命令 `python3 clash/rules-reconciler.py --simulate <domain/ip>` 快速离线调试。

### 4. 可视化自定义规则管理 (`rules-reconciler.py` & UI)
- 规则页原生集成自定义规则管理入口与操作抽屉。
- 支持 `DOMAIN-SUFFIX`、`DOMAIN`、`DOMAIN-KEYWORD`、`IP-CIDR`、`IP-CIDR6`、`GEOSITE`、`GEOIP` 等标准规则类型。
- 动态获取当前所有可用策略组供下拉选择。
- 规则语法实时生成预览、安全合法性校验（防字符注入）、删除二次确认与全字段 XSS 转义。

### 5. 多层安全与反脆弱保障
- **语法预检**：写入前自动调用 `mihomo -t` 对候选配置进行真实语法校验。
- **事务性回滚**：任一步骤失败（含 Controller 异常）自动通过历史备份原子恢复旧配置。
- **精准前缀剥离**：删除用户自定义规则时，不误伤订阅原有的同名规则。
- **NFS 跨进程排他锁**：使用 `fcntl.flock` 保障多并发操作安全。
- **恒定时间鉴权**：`consteq` 先对齐非空等长再 `secrets.compare_digest`，有效抵御时序分析攻击。
- **模块热重载**：网关检测到 Reconciler 与 Subscription Manager 脚本时间戳（`mtime`）变更时自动热重载，无需重启网关进程。

### 6. 安全 API 网关与双机跨节点协同 (`gateway.py`)
- 单源对外服务（静态资源托管 + API 反向代理 + WebSocket 流量转发）。
- 服务端注入 Mihomo `.controller-secret`，前端全程零 Secret 暴露。
- **双机集群智能路由**：自动识别本端环境（macOS 主机 / Linux VPS 主机），透明代理跨节点流量（如 `/panel/pxed/api/*` 与 `/panel/tebi/api/*`）。
- **NFS 静态字节缓存**：针对分布式 NFS 文件系统设计高效静态资源内存缓存，结合 `mtime_ns` / `size` 自动失效。

### 7. Keeper 守护协同 (`clash-keeper-loop.sh`)
- 每 120s 周期自检与重放。
- 基于 Hash 比对实现幂等合并：配置未变更时不写磁盘、不产生冗余备份、不触发重复 reload。
- 订阅覆盖或主配置重建后，用户规则自动保活重放。
- 仅调用 Mihomo Controller HTTP API（`PUT /configs?force=true`）进行无损热重载，确保独立代理栈零中断。

---

## 系统架构

```text
       [ 机场 A (YAML) ]     [ 机场 B (Base64) ]     [ 自建节点 (vless/hy2) ]
               │                     │                       │
               └─────────────────────┼───────────────────────┘
                                     ▼
      ┌─────────────────────────────────────────────────────────────┐
      │                        MihomoSuite                          │
      │                                                             │
      │  ┌─────────────────────────┐   ┌─────────────────────────┐  │
      │  │  subscription-manager   │   │    rules-reconciler     │  │
      │  │  · 格式清洗与广告过滤    │   │  · 分流推演仿真引擎     │  │
      │  │  · fcntl 原子文件锁     │   │  · 敏感服务 DNS 污染研判│  │
      │  └────────────┬────────────┘   └────────────┬────────────┘  │
      │               │                             │               │
      │               ▼                             ▼               │
      │  ┌───────────────────────────────────────────────────────┐  │
      │  │         Security Gateway & Diagnostics Engine         │  │
      │  │  · 恒定时间鉴权安全隔离   · 出口 IP / ISP 多源毫秒竞速  │  │
      │  └──────────────────────────┬────────────────────────────┘  │
      └─────────────────────────────┼───────────────────────────────┘
                                    │ 语法预检 (mihomo -t)
                                    │ 零感热重载 (PUT /configs?force=true)
                                    ▼
                         ┌──────────────────────┐
                         │  Mihomo 内核实例     │
                         └──────────────────────┘
```

---

## 目录结构

```text
.
├── clash/
│   ├── rules-reconciler.py         # 核心规则调度器 (校验、合并、事务回滚、Controller 热重载、分流/DNS推演)
│   ├── subscription-manager.py     # 订阅与节点聚合管理器 (多协议解析、垃圾过滤、命名隔离、原子输出)
│   ├── apply-local-import.py       # 本地节点持久化与注入脚本
│   └── clash-keeper-loop.sh        # Keeper 常驻守护脚本 (120s 周期幂等自检)
├── zashboard/
│   ├── gateway.py                  # 安全 API 网关 (鉴权、反向代理、WebSocket、静态缓存、多源竞速诊断)
│   ├── start-gateway.sh            # 网关启动包装脚本
│   ├── src/
│   │   └── user-rules-ui.js        # 前端扩展组件源码 (订阅管理、出口IP微标、规则推演栏、自定义规则Modal)
│   └── dist/                       # Web 面板静态资源产物
│       ├── assets/
│       │   └── user-rules-ui.js    # 生产构建后的扩展组件
│       └── index.html              # Web 面板单页入口
├── tests/
│   ├── test_auth.py                # 网关鉴权与时序安全测试
│   ├── test_cache.py               # NFS 静态缓存与性能测试
│   ├── test_gateway_endpoints.py   # 网关核心 API 端点功能测试
│   ├── test_reconciler_load.py     # Reconciler 模块动态热重载测试
│   ├── test_rule_simulation.py     # 规则分流与 DNS 污染推演测试
│   ├── test_subscription_manager.py # 订阅管理器全协议解析与聚合测试
│   └── test_ui_bundle.mjs          # 前端 DOM 注入与交互组件测试
├── Dockerfile                      # 生产级 Docker 容器构建文件
├── docker-compose.yml              # Docker Compose 一键编排文件
├── requirements.txt                # Python 依赖清单
└── package.json                    # 前端构建与测试套件配置
```

---

## 快速上手

### 环境准备
- Python 3.9+
- 已运行的 [Mihomo (Clash Meta)](https://github.com/MetaCubeX/mihomo) 内核（开启 External Controller）
- Linux / macOS 运行环境

### 安装与运行
```bash
# 1. 克隆仓库
git clone https://github.com/dengyie/mihomo-suite.git
cd mihomo-suite

# 2. 安装依赖
pip install -r requirements.txt

# 3. 初始化配置与口令
touch zashboard/panel.password      # 填入 Web 面板访问口令
touch clash/.controller-secret     # 填入与 Mihomo 对应的 External Controller Secret

# 4. 启动网关
chmod +x zashboard/start-gateway.sh clash/clash-keeper-loop.sh
./zashboard/start-gateway.sh
```

打开浏览器访问 `http://127.0.0.1:2053/panel/` 即可进入管理面板。

---

## Docker 容器化部署

```bash
# 启动容器
docker compose up -d

# 查看运行日志
docker compose logs -f
```

---

## REST API 接口规范

网关在 `/panel/api/*` 路径下提供 RESTful 接口体系，调用时携带 `Authorization: Bearer <PANEL_PASSWORD>` 请求头：

| 请求方法 | 接口路径 | 说明 | 请求体 / 查询参数示例 |
| :--- | :--- | :--- | :--- |
| `GET` | `/panel/api/subscriptions` | 获取全量订阅列表及元数据 | 无 |
| `POST` | `/panel/api/subscriptions` | 添加远程或本地订阅源 | `{"name":"Sub1","url":"https://...","exclude_filter":""}` |
| `POST` | `/panel/api/subscriptions/import-nodes` | 批量导入 RAW 节点 | `{"name":"Manual","text":"ss://...","skip_merge":true}` |
| `POST` | `/panel/api/subscriptions/<sub_id>/update` | 更新订阅配置或强制刷新拉取 | `{"name":"Sub1","refresh":true}` |
| `POST` | `/panel/api/subscriptions/<sub_id>/toggle` | 启用 / 停用指定订阅 | `{"enabled": true}` |
| `DELETE` | `/panel/api/subscriptions/<sub_id>` | 删除指定订阅并重新聚合 | 无 |
| `GET` | `/panel/api/diagnostics/egress-ip` | 出口 IP 多源竞速诊断与测速 | `?proxy=true&proxy_port=7897` |
| `POST` | `/panel/api/rules/simulate` | 规则分流匹配与 DNS 污染推演 | `{"domain": "api.openai.com"}` |
| `GET` | `/panel/api/user-rules` | 获取当前所有自定义规则列表 | 无 |
| `POST` | `/panel/api/user-rules` | 新增自定义规则并执行热重载 | `{"type":"DOMAIN-SUFFIX","payload":"anthropic.com","target":"PROXY"}` |
| `DELETE` | `/panel/api/user-rules/<rule_id>` | 删除自定义规则并执行热重载 | 无 |
| `GET` | `/panel/api/user-rules/targets` | 获取当前可用的全部策略组列表 | 无 |

---

## 命令行工具实战 (CLI)

### 订阅管理器 (`subscription-manager.py`)
```bash
# 查看所有已配置订阅与节点数量
python3 clash/subscription-manager.py --list

# 添加远程订阅源
python3 clash/subscription-manager.py --add "机场A" "https://example.com/api/v1/client/subscribe?token=xxx"

# 从纯文本/节点链接批量导入
python3 clash/subscription-manager.py --import-nodes "备用节点" "ss://YWVzLTI1Ni1nY206cGFzc0AxMi4zNC41Ni43ODo4Mzg4#HK-Node1"

# 手动更新指定订阅 (ID 通过 --list 查看)
python3 clash/subscription-manager.py --update "sub_xxxxxx"

# 强制全量重新拉取远程订阅并原子生成合并配置
python3 clash/subscription-manager.py --reconcile --fetch

# 删除指定订阅
python3 clash/subscription-manager.py --delete "sub_xxxxxx"
```

### 规则调度与推演器 (`rules-reconciler.py`)
```bash
# 模拟指定域名的分流策略与 DNS 解析（含 DNS 污染风险研判）
python3 clash/rules-reconciler.py --simulate "api.openai.com"
python3 clash/rules-reconciler.py --simulate "114.114.114.114"

# 指定特定配置文件进行推演
python3 clash/rules-reconciler.py --simulate "github.com" --config "/personal/clash/config.yaml"

# 列出当前配置中所有可用代理策略组 (Target)
python3 clash/rules-reconciler.py --list-targets

# 执行规则语法预检 (Dry Run)
python3 clash/rules-reconciler.py --dry-run

# 执行规则合并与 Controller 热重载
python3 clash/rules-reconciler.py --reconcile
```

---

## 自动化测试与质量保障

```bash
# 运行完整自动化测试套件 (包含 UI 测试与全部 Python 测试)
npm test

# 单独运行 Python 测试
python3 -m pytest tests/

# 单独运行前端 UI 模拟测试
node tests/test_ui_bundle.mjs
```

---

## 安全设计与隔离准则

- **密钥隔离机制**：生产环境真实密码（`panel.password`）与控制器密钥（`.controller-secret`）已严格纳入 `.gitignore`。首次部署时请在 `zashboard/panel.password` 与 `clash/.controller-secret` 中填入对应口令。服务端不会将口令注入 HTML，浏览器打开 `/panel/` 后在 Setup 中输入相同密码即可。
- **网络请求防御 (SSRF)**：订阅拉取仅允许 `http/https` 协议；解析后拒绝私网、环回（`127.0.0.1`）、链路本地及云厂商元数据地址；不跟随重定向；连接强绑定在校验时的 IP；响应体严格限制最大 8MiB。
- **Mihomo 反代限制**：`/panel/api` 仅转发面板实际使用的 Clash Meta 白名单路径；`/delay?url=` 仅放行 `generate_204` 与 `cloudflare trace` 探测目标。
- **配置与导入边界**：规则推演 `config_path` 严格限制在 `CLASH_ROOT` 目录内。死节点清理仅允许 `POST`，探测 `airports/local-nodes.yaml` 后写入 `disabled-nodes.txt` 并从该文件剔除失效节点。
- **客户端入站**：YAML 模板 `allow-lan` 默认设为 `false`；如需局域网共享，显式声明 `CLIENT_ALLOW_LAN=1`。
- **导入策略注入**：`apply-local-import.py` 默认读取 `airports/local-nodes.yaml`。节点文件仅存放 `proxies` 与简单名单 `groups`（`vps-import` / `google` / `grok`），上层策略由脚本编排。在缺失 `groups.vps-import` 时自动跳过，避免将全量节点意外合并到 VPS `本机导入` 策略中。

---

## 参与贡献与许可证

欢迎提交 Issue 和 Pull Request！
- 如遇到任何运行问题或发现 Bug，请提交 [GitHub Issue](https://github.com/dengyie/mihomo-suite/issues)。

本项目基于 [MIT License](LICENSE) 协议发布。
