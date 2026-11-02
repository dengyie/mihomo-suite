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

// Run main() inside a fresh context; get the transformed config back as JSON.
const script = new vm.Script(
  code +
    "\n;var __cfg = JSON.parse(__CONFIG_JSON__); main(__cfg); JSON.stringify(__cfg);"
);
const ctx = { __CONFIG_JSON__: JSON.stringify(config), console };
vm.createContext(ctx);
const outJson = script.runInContext(ctx);
const out = JSON.parse(outJson);
fs.writeFileSync(OUT_JSON, outJson);

const exclude = new Set(JSON.parse(fs.readFileSync(process.env.EXCLUDE_JSON || "/tmp/scripts/exclude.json", "utf8")));
const fail = [];
const ok = (cond, msg) => { if (!cond) fail.push(msg); };

const outNames = new Set((out.proxies || []).map((p) => p?.name).filter(Boolean));

// 1. all excluded names gone from proxies
for (const n of exclude) ok(!outNames.has(n), `proxy still present: ${n}`);

// 2. expected survivors
const mustHave = [
  "VLESS-Huawei-SH-Reality", "[share] 🇺🇸US-Vmess2(Bwh)", "🏠home-win-CF",
  "[tomorin] [anytls]VN Hanoi VNPT", "AnyTLS-googlevps", "[share] 🇭🇰HK-Warp1(Sak)",
  "[tomorin] US LAS Buyvm", "TUIC-Azure", "🇸🇬【亚洲】新加坡03丨直连",
];
for (const n of mustHave) ok(outNames.has(n), `alive node missing: ${n}`);
// 44 subscription survivors + 1 script-injected home-win-mesh
ok(outNames.size === 45, `proxy count ${outNames.size} != 45`);

// 3. mesh node injected and first member of 🏠家宽
ok(outNames.has("🏠home-win-mesh"), "home-win-mesh not injected");
const home = (out["proxy-groups"] || []).find((g) => g?.name === "🏠家宽");
ok(home && Array.isArray(home.proxies) && home.proxies[0] === "🏠home-win-mesh", "家宽 group mesh-first broken");

// 4. no group references excluded names / no empty groups
const groupNames = new Set((out["proxy-groups"] || []).map((g) => g?.name).filter(Boolean));
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

// 5. expected member counts
const expectCounts = { PROXY: 46, AUTO: 43, "🎯Google": 7, "🎯Claude": 9, "🎯OpenAI": 8, MangoCF: 3, "🏠家宽": 7 };
for (const [name, want] of Object.entries(expectCounts)) {
  const g = (out["proxy-groups"] || []).find((x) => x?.name === name);
  ok(g && (g.proxies || []).length === want, `group ${name}: ${(g && (g.proxies || []).length) || "missing"} != ${want}`);
}

// 6. rules sane
const rules = out.rules || [];
ok(rules.some((r) => /^MATCH,/.test(r)), "no MATCH rule");
ok(rules.some((r) => r.includes("🎯Claude")), "claude rules lost");
ok(rules.some((r) => r.includes("🎯OpenAI")), "openai rules lost");
ok(rules.some((r) => r.includes("mangoqwq.com")), "mangoqwq rules lost");
ok(rules.some((r) => r.includes("🏠家宽")), "home broadband rules lost");

if (fail.length) {
  console.error("FAIL (" + fail.length + "):");
  for (const f of fail) console.error("  - " + f);
  process.exit(1);
}
console.log(`HARNESS PASS: proxies=44, groups=${(out["proxy-groups"] || []).length}, rules=${rules.length}`);