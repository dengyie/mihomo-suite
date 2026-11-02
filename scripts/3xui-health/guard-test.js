#!/usr/bin/env node
// Regression test for the rule-referenced empty group guard (2026-11-02).
// Case: a group whose members are ALL dead and which is referenced by rules
// must survive (include-all-proxies fallback); an unreferenced empty group
// must still be dropped.
"use strict";
const fs = require("node:fs");
const vm = require("node:vm");

const SCRIPT = process.env.SCRIPT_JS || "/Users/mango/Library/Application Support/io.github.clash-verge-rev.clash-verge-rev/profiles/Script.js";
const SUB_JSON = process.env.SUB_JSON || "/tmp/scripts/sub.json";
const config = JSON.parse(fs.readFileSync(SUB_JSON, "utf8"));
const exclude = JSON.parse(fs.readFileSync(process.env.EXCLUDE_JSON || "/tmp/scripts/exclude.json", "utf8"));

// A node that the filter will remove.
const deadName = exclude[0];
const fail = [];
const ok = (cond, msg) => { if (!cond) fail.push(msg); };

// Sanity: the group we target is referenced by rules.
const rules = config.rules || [];
ok(rules.some((r) => r.endsWith(",🎯Claude")), "fixture: no rule references 🎯Claude");

// Case 1: rule-referenced group with only dead members.
const c1 = config["proxy-groups"].find((g) => g.name === "🎯Claude");
c1.proxies = [deadName];

// Case 2: unreferenced group with only dead members.
config["proxy-groups"].push({
  name: "🪦未引用的空组",
  type: "select",
  proxies: [deadName],
});

const code = fs.readFileSync(SCRIPT, "utf8");
const script = new vm.Script(
  code + "\n;var __cfg = JSON.parse(__CONFIG_JSON__); main(__cfg); JSON.stringify(__cfg);"
);
const ctx = { __CONFIG_JSON__: JSON.stringify(config), console };
vm.createContext(ctx);
const out = JSON.parse(script.runInContext(ctx));
fs.writeFileSync("/tmp/scripts/guard-after.json", JSON.stringify(out, null, 1));

const groups = out["proxy-groups"] || [];
const claude = groups.find((g) => g.name === "🎯Claude");
const orphan = groups.find((g) => g.name === "🪦未引用的空组");

ok(!!claude, "rule-referenced empty group was dropped (should survive)");
ok(claude && claude["include-all-proxies"] === true, "guard did not set include-all-proxies");
ok(!orphan, "unreferenced empty group survived (should be dropped)");
ok(!(out.proxies || []).some((p) => p.name === deadName), "dead node leaked");

if (fail.length) {
  console.error("GUARD TEST FAIL:");
  for (const f of fail) console.error("  - " + f);
  process.exit(1);
}
console.log("GUARD TEST PASS: rule-referenced group kept via include-all-proxies, unreferenced dropped");