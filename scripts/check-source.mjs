#!/usr/bin/env node
// 作者自检：用规则仓当前状态校验你仓库里的 sniff-rules.json（与收录时完全相同的检查）。
//
//   node <规则仓>/scripts/check-source.mjs --file sniff-rules.json [--repo owner/name] [--root <规则仓>]
//
// 命名空间取文件里的 namespace。已登记 → 使用 registry.json 认领的站点（--repo 不符则报错）；
// 未登记 → 使用文件里的 hosts 作为拟认领站点，并检查是否与已登记的认领冲突。
import { readFileSync, realpathSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { checkRepository, parseRegistry, parseRuleFile } from "./lib.mjs";

export function checkSource(root, text, { repo } = {}) {
  const parsed = parseRuleFile(text, "community", { source: true });
  if (parsed.errors.length > 0) return { ok: false, errors: parsed.errors };
  const registry = parseRegistry(readFileSync(join(root, "registry.json"), "utf8"));
  const ns = parsed.namespace;
  const entry = registry.sources.find((s) => s.ns === ns);
  const notes = [];
  let sources = registry.sources;
  if (entry) {
    if (repo && entry.repo.toLowerCase() !== repo.toLowerCase()) {
      return { ok: false, errors: [`命名空间 ${ns} 已由 ${entry.repo} 登记，换一个 namespace`] };
    }
    notes.push(`已登记：${entry.repo}，认领 ${entry.hosts.join(", ")}`);
  } else {
    if (!Array.isArray(parsed.hosts) || parsed.hosts.length === 0) {
      return { ok: false, errors: ["未登记的命名空间需要在文件里写 hosts（打算认领的站点），用于登记前自检"] };
    }
    sources = [...registry.sources, { ns, repo: repo ?? "owner/repo", hosts: parsed.hosts }];
    notes.push(`尚未登记：按 hosts ${parsed.hosts.join(", ")} 自检；通过后向规则仓提交登记 PR`);
  }
  const head = parseRegistry(JSON.stringify({ sources }));
  if (head.errors.length > 0) return { ok: false, errors: head.errors, notes };
  const check = checkRepository(root, { registry: head, override: { ns, text } });
  return { ok: check.errors.length === 0, errors: check.errors, notes, ruleCount: parsed.rules.length, testCount: parsed.tests.length };
}

if (process.argv[1] && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const argOf = (name) => {
    const i = process.argv.indexOf(name);
    return i >= 0 ? process.argv[i + 1] : undefined;
  };
  const file = argOf("--file");
  if (!file) {
    console.error("用法: check-source.mjs --file sniff-rules.json [--repo owner/name] [--root <规则仓>]");
    process.exit(2);
  }
  const root = resolve(argOf("--root") ?? new URL("..", import.meta.url).pathname);
  const result = checkSource(root, readFileSync(file, "utf8"), { repo: argOf("--repo") });
  for (const note of result.notes ?? []) console.log(note);
  if (result.ok) {
    console.log(`✅ 通过：${result.ruleCount} 条规则、${result.testCount} 条测试`);
  } else {
    console.error(`❌ 未通过（${result.errors.length} 项）：`);
    for (const error of result.errors) console.error(`  - ${error}`);
    process.exit(1);
  }
}
