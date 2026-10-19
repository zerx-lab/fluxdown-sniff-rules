#!/usr/bin/env node
// 把「提交社区规则」Issue 表单转成 rules/community/<站点>.json 的改动，并校验整个仓库。
//
//   node scripts/submit.mjs --event <GitHub issues 事件 JSON> --out <输出目录> [--root <dir>]
//
// 输出目录写入：
//   result.json  { ok, file, ruleIds, errors, warnings, prTitle, commitMessage }
//   comment.md   回复到 Issue 的说明
//   pr.md        PR 正文（仅 ok 时有意义）
// Issue 内容一律按数据处理：只做 JSON 解析与规则校验，不执行任何来自 Issue 的代码。
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, readdirSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { checkRepository } from "./lib.mjs";

/** Issue 表单字段标题；必须与 .github/ISSUE_TEMPLATE/community-rule.yml 的 label 完全一致。 */
export const FIELDS = {
  rule: "规则 JSON / Rule JSON",
  page: "示例页面 / Example page",
  samples: "示例资源地址 / Example resource URLs",
  tests: "测试用例 / Test cases",
  notes: "说明 / Notes",
};
const NO_RESPONSE = "_No response_";
/** 规则 id 去掉 `community.misc.` 后的部分（总长受扩展 id 规则 63 字符限制）。 */
const SUFFIX_RE = /^[a-z0-9][a-z0-9._-]{1,56}$/;

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/** 解析 Issue 表单正文：`### 标题` 分段，去掉代码围栏，`_No response_` 视为空。 */
export function parseIssueForm(body) {
  const sections = {};
  let current = null;
  let lines = [];
  const flush = () => {
    if (current === null) return;
    let text = lines.join("\n").trim();
    const fenced = text.match(/^```[a-zA-Z]*\n([\s\S]*?)\n?```$/);
    if (fenced) text = fenced[1].trim();
    sections[current] = text === NO_RESPONSE ? "" : text;
  };
  for (const line of String(body ?? "").replace(/\r\n/g, "\n").split("\n")) {
    const heading = line.match(/^###\s+(.+?)\s*$/);
    if (heading) {
      flush();
      current = heading[1];
      lines = [];
    } else if (current !== null) {
      lines.push(line);
    }
  }
  flush();
  return sections;
}

/**
 * 规则文件名：取第一条规则的 host / pageHost，去掉 `=`、`*.` 与 `www.`。
 * 有损清洗（含端口 / 路径 / 非 ASCII / 被截断）时追加原值的 6 位哈希，避免不同站点撞到同一个文件。
 */
export function fileSlug(rule) {
  const host = rule?.match?.host?.[0] ?? rule?.match?.pageHost?.[0];
  if (typeof host !== "string") return null;
  const original = host.trim().toLowerCase();
  const base = original.replace(/^=/, "").replace(/^\*\./, "").replace(/^www\./, "");
  const cleaned = base
    .replace(/[^a-z0-9.-]+/g, "-")
    .replace(/^[^a-z0-9]+/, "")
    .replace(/[^a-z0-9]+$/, "")
    .slice(0, 80);
  if (cleaned === "") return null;
  if (cleaned === base) return cleaned;
  const hash = createHash("sha256").update(original).digest("hex").slice(0, 6);
  return `${cleaned.slice(0, 73).replace(/[^a-z0-9]+$/, "")}-${hash}`;
}

/**
 * 把提交的规则转成规则仓托管的社区规则（命名空间 misc）。接受单条规则、规则数组、规则包或规则文件
 * （{ rules, tests }）。`local.x` / `community.x` / `community.misc.x` 统一改写为 `community.misc.x`；其它层级拒绝。
 */
export function toCommunityRules(input) {
  const errors = [];
  let list;
  let tests = [];
  if (Array.isArray(input)) list = input;
  else if (isRecord(input) && Array.isArray(input.rules)) {
    list = input.rules;
    if (Array.isArray(input.tests)) tests = input.tests;
  } else if (isRecord(input)) list = [input];
  else return { rules: [], tests: [], errors: ["规则 JSON 必须是规则对象、规则数组或 { rules: [...] }"] };
  if (list.length === 0) errors.push("没有规则");
  const rules = [];
  for (const [index, raw] of list.entries()) {
    if (!isRecord(raw) || typeof raw.id !== "string") {
      errors.push(`第 ${index + 1} 条规则缺少字符串 id`);
      continue;
    }
    const dot = raw.id.indexOf(".");
    const prefix = dot > 0 ? raw.id.slice(0, dot) : "";
    let suffix = dot > 0 ? raw.id.slice(dot + 1) : "";
    if (prefix === "community" && suffix.startsWith("misc.")) suffix = suffix.slice("misc.".length);
    if (prefix !== "local" && prefix !== "community") {
      errors.push(`${raw.id}：只能提交本地（local.*）或社区（community.*）规则`);
      continue;
    }
    if (!SUFFIX_RE.test(suffix)) {
      errors.push(`${raw.id}：id 名称部分只能含小写字母、数字、点、下划线、连字符（2–57 个字符）`);
      continue;
    }
    rules.push({ ...raw, id: `community.misc.${suffix}`, tier: "community" });
  }
  return { rules, tests, errors };
}

/**
 * 合并进已有规则文件：同 id 替换（内容变化时 version 取 max(提交值, 原值 + 1)），新 id 追加；
 * 测试按 name 替换或追加。
 */
export function mergeRuleFile(existing, rules, tests) {
  const merged = existing ? existing.rules.map((r) => ({ ...r })) : [];
  for (const rule of rules) {
    const at = merged.findIndex((r) => r.id === rule.id);
    if (at === -1) {
      merged.push({ ...rule, version: Number.isInteger(rule.version) && rule.version >= 1 ? rule.version : 1 });
      continue;
    }
    const before = merged[at];
    const same = JSON.stringify({ ...before, version: 0 }) === JSON.stringify({ ...rule, version: 0 });
    const submitted = Number.isInteger(rule.version) ? rule.version : 1;
    merged[at] = { ...rule, version: same ? before.version : Math.max(submitted, before.version + 1) };
  }
  const mergedTests = existing?.tests ? existing.tests.map((t) => ({ ...t })) : [];
  for (const test of tests) {
    const at = mergedTests.findIndex((t) => t.name === test?.name);
    if (at === -1) mergedTests.push(test);
    else mergedTests[at] = test;
  }
  return mergedTests.length > 0 ? { rules: merged, tests: mergedTests } : { rules: merged };
}

/** 记录每条社区规则的提交者（仓库根 owners.json），防止他人用同名 id 覆盖。 */
export const OWNERS_FILE = "owners.json";
/** 维护者给 Issue 加这个标签后，可覆盖他人提交的同名规则。 */
export const MAINTAINER_LABEL = "maintainer-override";
const MAX_SAMPLES = 20;

function readOwners(root) {
  const path = join(root, OWNERS_FILE);
  if (!existsSync(path)) return {};
  const parsed = JSON.parse(readFileSync(path, "utf8"));
  return isRecord(parsed) ? parsed : {};
}

function sortKeys(object) {
  return Object.fromEntries(Object.entries(object).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)));
}

function hasMaintainerLabel(issue) {
  return (issue.labels ?? []).some((label) => (typeof label === "string" ? label : label?.name) === MAINTAINER_LABEL);
}

/** 找出已收录该规则 id 的社区规则文件（相对路径）；没有返回 null。 */
function findRuleFile(root, id) {
  const dir = join(root, "rules", "community");
  if (!existsSync(dir)) return null;
  for (const name of readdirSync(dir).sort()) {
    if (!name.endsWith(".json")) continue;
    const parsed = JSON.parse(readFileSync(join(dir, name), "utf8"));
    if (Array.isArray(parsed?.rules) && parsed.rules.some((rule) => rule?.id === id)) return `rules/community/${name}`;
  }
  return null;
}

/**
 * 示例资源地址（每行一个）→ classifyResponse 测试：默认期望被识别为资源，行首加 `!` 表示期望不被任何规则识别（decision 为 none）。
 * 这样提交者不必手写测试 JSON，规则改坏时 CI 也会报警。
 */
export function parseSamples(text, pageUrl) {
  const errors = [];
  const tests = [];
  const lines = text.split("\n").map((line) => line.trim()).filter((line) => line !== "");
  if (lines.length > MAX_SAMPLES) errors.push(`示例资源地址最多 ${MAX_SAMPLES} 行`);
  for (const line of lines.slice(0, MAX_SAMPLES)) {
    const ignore = line.startsWith("!");
    const url = ignore ? line.slice(1).trim() : line;
    if (!/^https?:\/\//i.test(url) || hostOf(url) === null) {
      errors.push(`示例资源地址不是完整的 http(s) 地址：${url.slice(0, 120)}`);
      continue;
    }
    tests.push({
      name: `sample ${ignore ? "none" : "resource"}: ${url.slice(0, 160)}`,
      call: "classifyResponse",
      args: [{ url, pageUrl, size: 0, attachment: false }],
      expect: { decision: ignore ? "none" : "resource" },
    });
  }
  return { tests, errors };
}

function hostOf(url) {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return null;
  }
}

function hostMatches(host, pattern) {
  const exact = pattern.startsWith("=");
  const domain = (exact ? pattern.slice(1) : pattern).trim().toLowerCase();
  return exact ? host === domain : host === domain || host.endsWith(`.${domain}`);
}

/** 处理一次提交；写文件并返回结果（不负责 git / PR）。 */
export function processSubmission({ root, issue }) {
  const fields = parseIssueForm(issue.body);
  const errors = [];
  const warnings = [];
  const fail = () => ({ ok: false, file: null, ruleIds: [], errors, warnings });

  const ruleText = fields[FIELDS.rule] ?? "";
  if (ruleText === "") {
    errors.push(`缺少「${FIELDS.rule}」`);
    return fail();
  }
  let input;
  try {
    input = JSON.parse(ruleText);
  } catch (e) {
    errors.push(`规则 JSON 解析失败：${e.message}`);
    return fail();
  }
  const converted = toCommunityRules(input);
  errors.push(...converted.errors);
  let tests = converted.tests;
  const testText = fields[FIELDS.tests] ?? "";
  if (testText !== "") {
    try {
      const parsed = JSON.parse(testText);
      if (!Array.isArray(parsed)) errors.push("测试用例必须是 JSON 数组");
      else tests = [...tests, ...parsed];
    } catch (e) {
      errors.push(`测试用例 JSON 解析失败：${e.message}`);
    }
  }
  if (errors.length > 0) return fail();

  const sampleTests = [];
  const sampled = parseSamples(fields[FIELDS.samples] ?? "", fields[FIELDS.page] ?? "");
  errors.push(...sampled.errors);
  sampleTests.push(...sampled.tests);
  tests = [...tests, ...sampleTests];
  if (errors.length > 0) return fail();

  const slug = fileSlug(converted.rules[0]);
  if (slug === null) {
    errors.push("社区规则必须在 match.host 或 match.pageHost 中限定站点");
    return fail();
  }
  const pageHost = hostOf(fields[FIELDS.page] ?? "");
  if (pageHost === null) {
    errors.push(`「${FIELDS.page}」必须是完整的 http(s) 地址`);
    return fail();
  }
  const scoped = converted.rules.some((rule) =>
    [...(rule.match?.host ?? []), ...(rule.match?.pageHost ?? [])].some(
      (pattern) => typeof pattern === "string" && hostMatches(pageHost, pattern),
    ),
  );
  if (!scoped) warnings.push(`示例页面 ${pageHost} 不在任何一条规则的 host / pageHost 内，请确认站点范围`);

  const rel = `rules/community/${slug}.json`;
  const path = join(root, rel);
  const owners = readOwners(root);
  const override = hasMaintainerLabel(issue);
  let overrodeOwner = null;
  for (const rule of converted.rules) {
    const owner = owners[rule.id];
    const existingFile = findRuleFile(root, rule.id);
    if (existingFile === null || (owner && owner.id === issue.user.id)) continue;
    if (!override) {
      errors.push(
        `${rule.id} 已由${owner ? ` @${owner.login} ` : "维护者 / 他人"}提交（${existingFile}），不能覆盖；请换一个规则名称，或联系维护者加 \`${MAINTAINER_LABEL}\` 标签后重新校验`,
      );
    } else {
      overrodeOwner = owner?.login ?? "maintainer";
    }
  }
  if (errors.length > 0) return fail();
  const previousText = existsSync(path) ? readFileSync(path, "utf8") : null;
  const next = mergeRuleFile(previousText === null ? null : JSON.parse(previousText), converted.rules, tests);
  const text = `${JSON.stringify(next, null, 2)}\n`;
  mkdirSync(join(root, "rules", "community"), { recursive: true });
  writeFileSync(path, text);

  const check = checkRepository(root);
  if (check.errors.length > 0) {
    if (previousText === null) rmSync(path);
    else writeFileSync(path, previousText);
    errors.push(...check.errors);
    return { ...fail(), file: rel };
  }
  const nextOwners = { ...owners };
  for (const rule of converted.rules) nextOwners[rule.id] = { login: issue.user.login, id: issue.user.id };
  writeFileSync(join(root, OWNERS_FILE), `${JSON.stringify(sortKeys(nextOwners), null, 2)}\n`);
  return {
    ok: true,
    file: rel,
    ruleIds: converted.rules.map((rule) => rule.id),
    changed: previousText !== text,
    testCount: next.tests?.length ?? 0,
    sampleTestCount: sampleTests.length,
    overrodeOwner,
    errors,
    warnings,
  };
}

function renderComment(result, issue) {
  const lines = [];
  if (result.ok) {
    lines.push("✅ 规则已通过自动校验，已生成 / 更新 Pull Request，等待维护者审核。");
    lines.push("", `- 文件：\`${result.file}\``, `- 规则：${result.ruleIds.map((id) => `\`${id}\``).join("、")}`);
  } else {
    lines.push("❌ 自动校验未通过，请编辑本 Issue 修正后会自动重新校验：", "");
    for (const error of result.errors) lines.push(`- ${error}`);
  }
  if (result.warnings.length > 0) {
    lines.push("", "⚠️ 提醒：");
    for (const warning of result.warnings) lines.push(`- ${warning}`);
  }
  lines.push(
    "",
    `字段说明见 [嗅探规则文档](https://fluxdown.com/docs/zh/browser-extension/sniff-rules/)。（提交者 @${issue.user.login}）`,
  );
  return `${lines.join("\n")}\n`;
}

/** 把用户文本放进围栏代码块：打断其中的围栏，避免提前闭合。 */
function fenced(text) {
  return ["```text", text.replace(/```/g, "ʼʼʼ").trim(), "```"].join("\n");
}

function renderPr(result, issue, fields) {
  const lines = [
    `Closes #${issue.number}`,
    "",
    `社区规则提交，来自 @${issue.user.login}。已在提交流水线中通过 \`build.mjs\` 同款校验与规则测试。`,
    "",
    `- 文件：\`${result.file}\``,
    `- 规则：${result.ruleIds.map((id) => `\`${id}\``).join("、")}`,
    `- 示例页面：${fields[FIELDS.page] ?? ""}`,
    `- 自带测试：${result.testCount ?? 0} 条（其中由示例资源地址自动生成 ${result.sampleTestCount ?? 0} 条）`,
  ];
  if (result.overrodeOwner) lines.push(`- ⚠️ 覆盖了 ${result.overrodeOwner} 提交的规则（维护者已授权）`);
  const samples = fields[FIELDS.samples] ?? "";
  if (samples !== "") lines.push("", "### 示例资源地址", "", fenced(samples));
  const notes = fields[FIELDS.notes] ?? "";
  if (notes !== "") lines.push("", "### 提交者说明", "", fenced(notes));
  lines.push("", "审核要点：站点范围是否最小、选择器 / 正则是否稳定、是否会误判其它资源。", "");
  return lines.join("\n");
}

if (process.argv[1] && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const argOf = (name) => {
    const i = process.argv.indexOf(name);
    return i >= 0 ? process.argv[i + 1] : undefined;
  };
  const eventPath = argOf("--event");
  const out = argOf("--out");
  if (!eventPath || !out) {
    console.error("用法: submit.mjs --event <event.json> --out <dir> [--root <dir>]");
    process.exit(2);
  }
  const root = resolve(argOf("--root") ?? ".");
  const { issue } = JSON.parse(readFileSync(eventPath, "utf8"));
  const result = processSubmission({ root, issue });
  const fields = parseIssueForm(issue.body);
  const coAuthor = `${issue.user.login} <${issue.user.id}+${issue.user.login}@users.noreply.github.com>`;
  const title = String(issue.title ?? "").replace(/\s+/g, " ").trim().slice(0, 120);
  mkdirSync(out, { recursive: true });
  writeFileSync(
    join(out, "result.json"),
    JSON.stringify({
      ...result,
      prTitle: `community: ${title || result.ruleIds.join(", ")}`,
      commitMessage: `community: ${result.ruleIds.join(", ")} (#${issue.number})\n\nCo-authored-by: ${coAuthor}\n`,
    }),
  );
  writeFileSync(join(out, "comment.md"), renderComment(result, issue));
  writeFileSync(join(out, "pr.md"), renderPr(result, issue, fields));
  console.log(result.ok ? `通过：${result.file}` : `未通过：\n${result.errors.join("\n")}`);
}
