#!/usr/bin/env node
// 收录登记仓库：读取每个登记仓库的 Latest Release → 校验 → 写入 sources/<ns>/ 快照与 pin。
//
//   node scripts/stage.mjs [--root <dir>] [--results <file>] [--sync-issues <owner/repo>]
//
// 环境变量 GITHUB_TOKEN 用于 GitHub API。某个仓库收录失败时保留它已收录的版本，并记入 results.failures；
// --sync-issues 再据此开 / 更新 / 关闭 stage-fail issue。从 registry.json 删除的命名空间同时删除快照（下架）。
import { existsSync, mkdirSync, readFileSync, readdirSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { fetchLatestRelease, syncFailIssues } from "./github.mjs";
import { checkRepository, parseRegistry, parseRuleFile, sourcePaths, versionRegressions } from "./lib.mjs";

function readJson(path) {
  return existsSync(path) ? JSON.parse(readFileSync(path, "utf8")) : null;
}

/**
 * 对一个登记仓库做一次收录判定（不访问网络；release 由调用方取得）。
 * 返回 { status: "unchanged" | "updated" | "failed", errors? }，updated 时已写入快照。
 */
export function stageOne(root, entry, release, { now = Date.now() } = {}) {
  if (!release.ok) return { status: "failed", errors: [release.error] };
  const paths = sourcePaths(root, entry.ns);
  const pin = readJson(paths.pin);
  if (pin && pin.repo === entry.repo && pin.tag === release.tag) {
    if (pin.sha256 === release.sha256) return { status: "unchanged" };
    return { status: "failed", errors: [`已收录的 Release ${release.tag} 的附件被替换（摘要变化）。请发布新的 Release，不要改动旧 Release 的附件`] };
  }
  if (pin && pin.repo === entry.repo && !(Date.parse(release.publishedAt) > Date.parse(pin.publishedAt))) {
    return { status: "failed", errors: [`最新 Release ${release.tag} 不比已收录的 ${pin.tag} 新`] };
  }
  const parsed = parseRuleFile(release.text, "community", { source: true });
  if (parsed.errors.length > 0) return { status: "failed", errors: parsed.errors };
  if (existsSync(paths.rules)) {
    const previous = parseRuleFile(readFileSync(paths.rules, "utf8"), "community", { source: true });
    const regressions = versionRegressions(previous.rules, parsed.rules);
    if (regressions.length > 0) return { status: "failed", errors: regressions };
  }
  const check = checkRepository(root, { override: { ns: entry.ns, text: release.text } });
  if (check.errors.length > 0) return { status: "failed", errors: check.errors };
  mkdirSync(paths.dir, { recursive: true });
  writeFileSync(paths.rules, release.text);
  writeFileSync(
    paths.pin,
    `${JSON.stringify({ repo: entry.repo, tag: release.tag, publishedAt: release.publishedAt, url: release.url, sha256: release.sha256, stagedAt: new Date(now).toISOString() }, null, 2)}\n`,
  );
  return { status: "updated" };
}

/** 收录全部登记仓库。fetchRelease(repo) 可注入（测试用）。 */
export async function stageAll(root, { fetchRelease, now = Date.now() } = {}) {
  const registry = parseRegistry(readFileSync(join(root, "registry.json"), "utf8"));
  if (registry.errors.length > 0) throw new Error(`registry.json 无效：\n${registry.errors.join("\n")}`);
  const results = { updated: [], removed: [], failures: {}, healthy: [] };

  const registered = new Set(registry.sources.map((s) => s.ns));
  const sourcesDir = join(root, "sources");
  if (existsSync(sourcesDir)) {
    for (const ns of readdirSync(sourcesDir)) {
      if (!ns.startsWith(".") && !registered.has(ns)) {
        rmSync(join(sourcesDir, ns), { recursive: true, force: true });
        results.removed.push(ns);
      }
    }
  }
  const baseline = checkRepository(root);
  if (baseline.errors.length > 0) throw new Error(`收录前仓库已不通过校验：\n${baseline.errors.join("\n")}`);

  for (const entry of registry.sources) {
    const outcome = stageOne(root, entry, await fetchRelease(entry.repo), { now });
    if (outcome.status === "failed") results.failures[entry.ns] = { repo: entry.repo, errors: outcome.errors };
    else {
      results.healthy.push(entry.ns);
      if (outcome.status === "updated") results.updated.push({ ns: entry.ns, tag: readJson(sourcePaths(root, entry.ns).pin).tag });
    }
  }
  return results;
}

export function summary(results) {
  const parts = [
    ...results.updated.map((u) => `${u.ns} ${u.tag}`),
    ...results.removed.map((ns) => `remove ${ns}`),
  ];
  return parts.length > 0 ? `stage: ${parts.join(", ")}` : null;
}

if (process.argv[1] && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const argOf = (name) => {
    const i = process.argv.indexOf(name);
    return i >= 0 ? process.argv[i + 1] : undefined;
  };
  const root = resolve(argOf("--root") ?? ".");
  const token = process.env.GITHUB_TOKEN;
  const results = await stageAll(root, { fetchRelease: (repo) => fetchLatestRelease(repo, { token }) });
  for (const u of results.updated) console.log(`已收录 ${u.ns} ${u.tag}`);
  for (const ns of results.removed) console.log(`已下架 ${ns}`);
  for (const [ns, f] of Object.entries(results.failures)) console.log(`收录失败 ${ns}（${f.repo}）：\n  ${f.errors.join("\n  ")}`);
  const resultsFile = argOf("--results");
  if (resultsFile) writeFileSync(resultsFile, JSON.stringify({ ...results, message: summary(results) }));
  const issueRepo = argOf("--sync-issues");
  if (issueRepo) await syncFailIssues(issueRepo, results, { token });
}
