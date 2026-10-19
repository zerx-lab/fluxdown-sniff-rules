#!/usr/bin/env node
// 登记 PR 检查：对比 PR 里的 registry.json 与 main 上的版本，对新增 / 改动的条目实际拉取其 Latest Release
// 做一次与收录完全相同的检查，结果写成 PR 评论。
//
//   node scripts/check-registry.mjs --head <PR 的 registry.json> [--author <PR 作者>] [--files <改动文件列表>] --out <comment.md>
//
// 只读取 PR 的 registry.json 作为数据，不执行 PR 中的任何代码。退出码 1 表示检查不通过。
import { readFileSync, realpathSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { fetchLatestRelease } from "./github.mjs";
import { checkRepository, parseRegistry } from "./lib.mjs";

/** 纯判定：返回 { ok, lines }；fetchRelease 可注入。 */
export async function checkRegistryChange(root, headText, { author, files = [], fetchRelease }) {
  const lines = [];
  const errors = [];
  const warnings = [];
  const extra = files.filter((f) => f !== "registry.json");
  if (extra.length > 0) errors.push(`登记 PR 只能修改 registry.json，请把以下改动移到单独的 PR：${extra.join("、")}`);
  const base = parseRegistry(readFileSync(join(root, "registry.json"), "utf8"));
  const head = parseRegistry(headText);
  errors.push(...head.errors);
  const before = new Map(base.sources.map((s) => [s.ns, s]));
  const after = new Set(head.sources.map((s) => s.ns));
  const changed = [];
  for (const entry of head.sources) {
    const old = before.get(entry.ns);
    if (!old) {
      changed.push({ entry, kind: "新增" });
      const owner = entry.repo.split("/")[0].toLowerCase();
      if (author && owner !== author.toLowerCase()) {
        warnings.push(`${entry.ns}：PR 作者 @${author} 不是仓库 ${entry.repo} 的 owner，维护者需确认已获仓库所有者同意`);
      }
    } else if (old.repo !== entry.repo) {
      changed.push({ entry, kind: "更换仓库" });
      warnings.push(`${entry.ns}：仓库从 ${old.repo} 改为 ${entry.repo}，需原维护者 @${old.repo.split("/")[0]} 在本 PR 中确认`);
    } else if (JSON.stringify(old.hosts) !== JSON.stringify(entry.hosts)) {
      changed.push({ entry, kind: "修改认领站点" });
      const added = entry.hosts.filter((h) => !old.hosts.includes(h));
      if (added.length > 0) warnings.push(`${entry.ns}：新增认领 ${added.join(", ")}，请审核是否合理`);
    } else if (old.description !== entry.description) {
      changed.push({ entry, kind: "修改说明", skipFetch: true });
    }
  }
  for (const ns of before.keys()) if (!after.has(ns)) lines.push(`- 🗑️ 下架 \`${ns}\`：合并后收录任务会删除其规则`);

  if (head.errors.length === 0) {
    for (const { entry, kind, skipFetch } of changed) {
      if (skipFetch) {
        lines.push(`- ✏️ ${kind} \`${entry.ns}\``);
        continue;
      }
      const release = await fetchRelease(entry.repo);
      if (!release.ok) {
        errors.push(`${entry.ns}（${entry.repo}）：${release.error}`);
        continue;
      }
      const check = checkRepository(root, { registry: head, override: { ns: entry.ns, text: release.text } });
      if (check.errors.length > 0) {
        for (const error of check.errors) errors.push(`${entry.ns}（${entry.repo} ${release.tag}）：${error}`);
        continue;
      }
      const ours = check.sources.rules.community.filter((r) => String(r.id).startsWith(`community.${entry.ns}.`));
      lines.push(
        `- ✅ ${kind} \`${entry.ns}\` → [${entry.repo}](https://github.com/${entry.repo}) ${release.tag}：${ours.length} 条规则通过校验与测试；认领 ${entry.hosts.map((h) => `\`${h}\``).join(" ")}`,
      );
      for (const rule of ours) lines.push(`  - \`${rule.id}\` v${rule.version} · ${rule.stage}/${rule.action?.kind}${rule.title ? ` · ${rule.title}` : ""}`);
    }
  }

  const out = [errors.length === 0 ? "### ✅ 登记检查通过" : "### ❌ 登记检查未通过", ""];
  if (lines.length > 0) out.push(...lines, "");
  if (errors.length > 0) out.push("**需要修正：**", ...errors.map((e) => `- ${e}`), "");
  if (warnings.length > 0) out.push("**请维护者留意：**", ...warnings.map((w) => `- ${w}`), "");
  out.push("修正后向本 PR 推送新的提交（或在登记仓库发布新 Release 后重新运行检查）即可重新检查。说明：https://fluxdown.com/docs/zh/contributing/sniff-rules/");
  return { ok: errors.length === 0, comment: `${out.join("\n")}\n` };
}

if (process.argv[1] && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const argOf = (name) => {
    const i = process.argv.indexOf(name);
    return i >= 0 ? process.argv[i + 1] : undefined;
  };
  const headPath = argOf("--head");
  const out = argOf("--out");
  if (!headPath || !out) {
    console.error("用法: check-registry.mjs --head <registry.json> [--author <login>] [--files <列表文件>] --out <comment.md> [--root <dir>]");
    process.exit(2);
  }
  const root = resolve(argOf("--root") ?? ".");
  const filesPath = argOf("--files");
  const files = filesPath ? readFileSync(filesPath, "utf8").split("\n").filter(Boolean) : [];
  const result = await checkRegistryChange(root, readFileSync(headPath, "utf8"), {
    author: argOf("--author"),
    files,
    fetchRelease: (repo) => fetchLatestRelease(repo, { token: process.env.GITHUB_TOKEN }),
  });
  writeFileSync(out, result.comment);
  console.log(result.comment);
  if (!result.ok) process.exit(1);
}
