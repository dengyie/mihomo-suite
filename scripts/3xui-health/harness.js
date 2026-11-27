#!/usr/bin/env node
// Harness: run patched Script.js main() against the real 3x-ui subscription
// config and assert the dead-node filter behaved correctly.
"use strict";
const fs = require("node:fs");
const vm = require("node:vm");

const SCRIPT = process.env.SCRIPT_JS || "/Users/mango/Library/Application Support/io.github.clash-verge-rev.clash-verge-rev/profiles/Script.js";
const SUB_JSON = process.env.SUB_JSON || "/tmp/scripts/sub.json";
const OUT_JSON = process.env.OUT_JSON || "/tmp/scripts/after.json";

const config = JSON.parse(fs.readFileSync(SUB_JSON, "utf8"));
const code = fs.readFileSync(SCRIPT, "utf8");

// Run main() inside a fresh context; get the transformed config back as JSON, plus DEAD_NODES_3XUI.
const script = new vm.Script(
  code +
    "\n;var __cfg = JSON.parse(__CONFIG_JSON__); main(__cfg); JSON.stringify({ out: __cfg, dead: [...DEAD_NODES_3XUI] });"
);
const ctx = { __CONFIG_JSON__: JSON.stringify(config), console };
vm.createContext(ctx);
const runResult = JSON.parse(script.runInContext(ctx));
const out = runResult.out;
const outJson = JSON.stringify(out);
fs.writeFileSync(OUT_JSON, outJson);

const excludePath = process.env.EXCLUDE_JSON || "/tmp/scripts/exclude.json";
const exclude = new Set(
  fs.existsSync(excludePath) ? JSON.parse(fs.readFileSync(excludePath, "utf8")) : runResult.dead
);
const fail = [];
const ok = (cond, msg) => { if (!cond) fail.push(msg); };

const outNames = new Set((out.proxies || []).map((p) => p?.name).filter(Boolean));

// 1. all excluded names gone from proxies
for (const n of exclude) ok(!outNames.has(n), `proxy still present: ${n}`);
ok(!outNames.has("🏠home-win-CF") && !outNames.has("[自建] 🏠home-win-CF"), "legacy home-win-CF still present");

// 2. expected survivors -- self-built nodes may carry the optional "[自建] " tag
const SELF_TAG = "[自建] ";
const mustHave = [
  "VLESS-Huawei-SH-Reality", "[share] 🇺🇸US-Vmess2(Bwh)", "🏠home-win-mesh",
  "[tomorin] [anytls]VN Hanoi VNPT", "AnyTLS-googlevps", "[share] 🇭🇰HK-Warp1(Sak)",
  "[tomorin] US LAS Buyvm", "TUIC-Azure", "🇺🇸PIGEONW-家宽-01",
];
// self-built names carry "[自建] " + optional region flag; airport names keep their flag
const stripTag = (n) => {
  if (!n.startsWith(SELF_TAG)) return n;
  return n.slice(SELF_TAG.length).replace(/^[\u{1F1E6}-\u{1F1FF}]{2}/u, "");
};
for (const n of mustHave) {
  ok([...outNames].some((x) => stripTag(x) === n), `alive node missing: ${n}`);
}
// Every non-excluded input proxy must survive + injected home-win-mesh + NP_PIGEONW nodes
const rawInputNames = new Set((config.proxies || []).map((p) => p?.name).filter(Boolean));
for (const n of rawInputNames) {
  if (!exclude.has(n)) ok(outNames.has(n), `non-excluded proxy dropped: ${n}`);
}
ok(outNames.size === 95, `proxy count ${outNames.size} != 95`);

// 3. mesh node injected and first member of 🏠家宽 (no CF fallback)
const MESH = "🏠home-win-mesh";
ok(outNames.has(MESH), "home-win-mesh not injected");
const home = (out["proxy-groups"] || []).find((g) => g?.name === "🏠家宽");
ok(home && Array.isArray(home.proxies) && home.proxies[0] === MESH, "家宽 group mesh-first broken");
ok(home && !home.proxies.some((m) => m.includes("home-win-CF")), "家宽 group still references home-win-CF");

// 4. no group references excluded names / no empty groups
const groupNames = new Set((out["proxy-groups"] || []).map((g) => g?.name).filter(Boolean));
ok(!groupNames.has("MangoCF"), "legacy MangoCF group still present");
for (const g of out["proxy-groups"] || []) {
  const members = g.proxies || [];
  for (const m of members) {
    ok(!exclude.has(m), `group ${g.name} references excluded ${m}`);
    ok(outNames.has(m) || groupNames.has(m) || ["DIRECT","REJECT","REJECT-DROP","PASS","COMPATIBLE","GLOBAL"].includes(m),
       `group ${g.name} has dangling member ${m}`);
  }
  const keepsAll = g["include-all"] || g["include-all-proxies"] || g["include-all-providers"];
  ok(keepsAll || members.length > 0 || (g.use || []).length > 0, `group ${g.name} is empty`);
}

// 5. expected member counts (snapshot-coupled: re-pin when sub.json is refreshed)
// REV 18: 🎯Claude/🎯OpenAI/🎯Meta merged into 🎯美国; per-host gradients are hidden fallbacks.
const US = "🎯美国";
const expectCounts = JSON.parse(process.env.EXPECT_COUNTS || "null") || { PROXY: 96, "🎯Google": 32, [US]: 33, "🏠家宽": 2 };
for (const [name, want] of Object.entries(expectCounts)) {
  const g = (out["proxy-groups"] || []).find((x) => x?.name === name);
  ok(g && (g.proxies || []).length === want, `group ${name}: ${(g && (g.proxies || []).length) || "missing"} != ${want}`);
}

// 6. rules sane
const rules = out.rules || [];
ok(rules.some((r) => /^MATCH,/.test(r)), "no MATCH rule");
ok(rules.some((r) => r === "DOMAIN-SUFFIX,claude.ai," + US), "claude rules lost");
ok(rules.some((r) => r === "DOMAIN-SUFFIX,openai.com," + US), "openai rules lost");
ok(!rules.some((r) => /🎯(Claude|OpenAI|Meta)(,|$)/.test(r)), "rule still targets a legacy US group");
// 7. exposed set: only curated groups are visible in the panel
const EXPOSED = new Set(["PROXY", "🎯Google", US, "🎯ZCode", "🌏港澳台优选", "🏠家宽", "GLOBAL"]);
for (const g of out["proxy-groups"] || []) {
  ok(EXPOSED.has(g.name) || g.hidden === true, `group ${g.name} is exposed but not in the curated set`);
}
ok(!rules.some((r) => /MangoCF|mangoqwq\.com/i.test(r)), "legacy MangoCF/mangoqwq.com rule still present");
ok(rules.some((r) => r.includes("🏠家宽")), "home broadband rules lost");

if (fail.length) {
  console.error("FAIL (" + fail.length + "):");
  for (const f of fail) console.error("  - " + f);
  process.exit(1);
}
console.log(`HARNESS PASS: proxies=${outNames.size}, groups=${(out["proxy-groups"] || []).length}, rules=${rules.length}`);