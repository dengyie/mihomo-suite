# 3x-ui 节点健康检测工具链

对 Clash Verge 里 3x-ui 订阅（`mango-clash`，uid `RBqg7ki8l5g7`）做全节点测活，
把确认死亡的节点写进全局 `Script.js` 的 `DEAD_NODES_3XUI` 黑名单。

## 背景：为什么要写进 Script.js 而不是改订阅文件

- 该订阅 `allow_auto_update: true`，**直接改缓存文件 `profiles/RBqg7ki8l5g7.yaml`
  会在下次自动更新时被覆盖**，死节点复活。
- 全局 `Script.js`（`enable_builtin_enhanced: true` 时对所有配置生效）是唯一
  长期生效的位置；`main()` 开头的 `dropDeadNodes()` 删节点，
  `pruneProxyGroups()` 自动把组员对账清干净。
- ⚠️ 名单必须**指纹门控**（`MangoCF` 组 / `🏠home-win-CF` 节点）：
  草莓订阅 `RT86t6ly58RD` 和宝可梦订阅 `Ri4BTq8ZwowL` 有同名节点但服务器不同，
  按名字全局删会误伤。

## 文件

| 文件 | 作用 |
|---|---|
| `confirm_dead.py` | 主力测活：走 mihomo Unix socket API，5s 双源两轮 → 失败的再 8s 长超时复核 → 输出 `{alive, slow, dead}` JSON |
| `tiebreak.py` | 仲裁抖动节点：10s 超时 × 12 次探测，≥3 次命中则保留 |
| `harness.js` | 逻辑验收：在 Node VM 里跑真实 `Script.js` 的 `main()`，断言死节点清除、幸存节点在位、无悬空组员、无空组、规则完整 |
| `guard-test.js` | 回归测试：规则引用的空组必须保留（`include-all-proxies` 兜底），未被引用的空组必须丢弃 |

## 用法

```bash
# 1. 拉最新订阅并转 JSON（供 harness 使用）
curl -sL "https://3x-ui.mangoqwq.com/sub/clash?token=<TOKEN>" -o /tmp/dl-3xui/sub.yaml
python3 -c "import yaml,json;json.dump(yaml.safe_load(open('/tmp/dl-3xui/sub.yaml')),open('/tmp/scripts/sub.json','w'),ensure_ascii=False)"

# 2. 测活（需 Clash Verge 内核运行中）
python3 scripts/3xui-health/confirm_dead.py
python3 scripts/3xui-health/tiebreak.py          # 有抖动节点时跑

# 3. 生成 exclude.json 并把新名字同步进 Script.js 的 DEAD_NODES_3XUI

# 4. 验收
node scripts/3xui-health/harness.js
node scripts/3xui-health/guard-test.js
"/Applications/Clash Verge.app/Contents/MacOS/verge-mihomo" -t -f /tmp/scripts/after-test.yaml
```

## 实测结论（2026-11-02）

118 节点 → 存活 41（34.7%），死亡 74。

- **「机场BGP」整批 36 个全灭**：3x-ui 聚合时用了已失效的入口域名
  `api.strawberrymemo.com`；草莓官方订阅走 `lb.download.strawberrymemo.com`。
  BGP 系整批同理——共 29 个草莓系节点，已拆成独立数组
  `DEAD_STRAWBERRY_BGP`，**面板入口修好后带同名字新增服务器即可整批复活**。
- `[share]` 组 24 个里 19 个死亡（55–66%），该机场下架严重。
- `[tomorin]` 组 24 个里 18 个存活，最稳。
- 国内直连 Reality 系列（Huawei/Tencent/Tebi/Azure）全部存活，40–150ms。

## 注意

- 浮动节点（`AnyTLS-googlevps`、`VN Hanoi ×2`）仲裁时已保留。
- Script.js 是全局脚本，任何名字命中都会在该指纹生效的配置里删除；
  改名单前先确认没有其他订阅复用同名。
- 每次改动前 `Script.js` 都有时间戳备份，回滚直接覆盖即可。
