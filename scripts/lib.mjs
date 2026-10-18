// 规则仓核心：读取规则源（官方、misc、登记仓库快照）→ 校验 → 跑规则测试 → 组装规则包 / 吊销列表 → 签名。
// 校验与求值用 vendor/fluxdown-sniff-rules.mjs（由 FluxDown 仓库从扩展源码打包），与扩展行为一致。
import { createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import {
  BUILTIN_PACK,
  PackRejectedError,
  RULE_ENGINE_VERSION,
  compileRules,
  hostMatchesPattern,
  parseHostPattern,
  validatePack,
} from "../vendor/fluxdown-sniff-rules.mjs";

/** 规则仓托管的社区命名空间（Issue 表单提交的规则都在这里）。 */
export const MISC_NS = "misc";
/** 登记仓库不能使用的命名空间。 */
export const RESERVED_NS = new Set([MISC_NS, "official", "builtin", "fluxdown", "community", "local", "plugin", "test"]);
export const NS_RE = /^[a-z0-9][a-z0-9-]{1,30}$/;
/** 登记仓库发布的 Release 附件名。 */
export const SOURCE_ASSET = "sniff-rules.json";
export const REPO_RE = /^[A-Za-z0-9-]{1,39}\/[A-Za-z0-9._-]{1,100}$/;
/** 规则文件名：小写字母 / 数字开头，只含小写字母、数字、点、连字符。 */
export const FILE_NAME_RE = /^[a-z0-9][a-z0-9.-]{0,79}\.json$/;
const RULE_ID_RE = /^(builtin|official|plugin|community|local)\.[a-z0-9][a-z0-9._-]{1,62}$/;
const DAY_MS = 24 * 60 * 60 * 1000;
/** 社区包与吊销列表的有效期；剩余不足 RENEW_WITHIN 时重新签发。 */
export const EXPIRY_MS = 30 * DAY_MS;
export const RENEW_WITHIN_MS = 14 * DAY_MS;
/** 与 FluxDown agent `sniff_rules/verify.rs` 的上限一致。 */
export const MAX_PACK_PAYLOAD_BYTES = 400 * 1024;
const MAX_REVOCATION_PAYLOAD_BYTES = 64 * 1024;
const MAX_REVOCATION_ENTRIES = 5000;
const MAX_TESTS_PER_FILE = 200;
const MAX_CLAIMS = 32;
const TEST_CALLS = new Set([
  "classifyResponse",
  "classify",
  "isIgnored",
  "dedupeKey",
  "fileExtension",
  "trackKind",
  "bodyWatchers",
  "extractFromBody",
  "manifestsFromBody",
  "domRules",
  "pageHints",
  "requestHeaders",
  "mirrorGroups",
]);
/** 测试时引擎的默认时间：远离任何有效期边界，结果不随运行日期变化。 */
const TEST_NOW = Date.parse("2026-01-01T00:00:00Z");

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/** 规则 id 的命名空间：`community.<ns>.<名字>` → ns；不是这个形状返回 null。 */
export function namespaceOf(id) {
  const match = /^community\.([a-z0-9-]+)\./.exec(String(id));
  return match ? match[1] : null;
}

// ===== 站点认领 =====

/** 认领是普通域名（含全部子域），至少两段、不带 `=` / 通配。 */
export function parseClaim(claim) {
  if (typeof claim !== "string" || claim.startsWith("=") || claim.includes("*")) return null;
  const pattern = parseHostPattern(claim);
  if (!pattern || !pattern.domain.includes(".")) return null;
  return pattern.domain;
}

/** 规则里的 host 模式（`a.com` / `=a.com`）是否落在某个认领域名（含子域）内。 */
export function withinClaims(pattern, claims) {
  const parsed = parseHostPattern(pattern);
  if (!parsed) return false;
  return claims.some((claim) => hostMatchesPattern(parsed.domain, { domain: claim, exact: false }));
}

function claimsOverlap(a, b) {
  return a === b || a.endsWith(`.${b}`) || b.endsWith(`.${a}`);
}

/** 规则用到的全部站点模式：match / exclude 的 host、pageHost 与 mirror.hosts。 */
function rulePatterns(rule) {
  const out = [];
  for (const m of [rule.match, ...(Array.isArray(rule.exclude) ? rule.exclude : [])]) {
    if (!isRecord(m)) continue;
    for (const key of ["host", "pageHost"]) if (Array.isArray(m[key])) out.push(...m[key]);
  }
  if (rule.action?.kind === "mirror" && Array.isArray(rule.action.hosts)) out.push(...rule.action.hosts);
  return out.filter((p) => typeof p === "string");
}

// ===== registry.json =====

/**
 * 解析登记表：`{ "sources": [{ ns, repo, hosts, description? }] }`。
 * 检查命名空间格式 / 保留字 / 唯一、仓库格式 / 唯一、认领域名合法且各命名空间之间互不重叠。
 */
export function parseRegistry(text) {
  const errors = [];
  let doc;
  try {
    doc = JSON.parse(text);
  } catch (e) {
    return { sources: [], errors: [`registry.json 不是合法 JSON：${e.message}`] };
  }
  if (!isRecord(doc) || !Array.isArray(doc.sources)) {
    return { sources: [], errors: ['registry.json 必须是 { "sources": [] }'] };
  }
  for (const key of Object.keys(doc)) if (key !== "sources" && key !== "$schema") errors.push(`registry.json：未知字段 ${key}`);
  const sources = [];
  const seenNs = new Set();
  const seenRepo = new Set();
  for (const [index, entry] of doc.sources.entries()) {
    const where = `sources[${index}]`;
    if (!isRecord(entry)) {
      errors.push(`${where} 不是对象`);
      continue;
    }
    for (const key of Object.keys(entry)) {
      if (!["ns", "repo", "hosts", "description"].includes(key)) errors.push(`${where}：未知字段 ${key}`);
    }
    const { ns, repo, hosts, description } = entry;
    if (typeof ns !== "string" || !NS_RE.test(ns)) {
      errors.push(`${where}.ns 只能含小写字母、数字、连字符（2–31 个字符）`);
      continue;
    }
    if (RESERVED_NS.has(ns)) errors.push(`${where}.ns「${ns}」是保留字`);
    if (seenNs.has(ns)) errors.push(`${where}.ns「${ns}」重复`);
    seenNs.add(ns);
    if (typeof repo !== "string" || !REPO_RE.test(repo)) errors.push(`${where}.repo 必须是 owner/name`);
    else if (seenRepo.has(repo.toLowerCase())) errors.push(`${where}.repo「${repo}」已被其它命名空间登记`);
    else seenRepo.add(repo.toLowerCase());
    if (!Array.isArray(hosts) || hosts.length === 0 || hosts.length > MAX_CLAIMS) {
      errors.push(`${where}.hosts 必须是 1–${MAX_CLAIMS} 个域名`);
      continue;
    }
    const claims = [];
    for (const host of hosts) {
      const claim = parseClaim(host);
      if (claim === null) errors.push(`${where}.hosts：「${String(host)}」不是合法域名（不要带 =、*、协议或路径）`);
      else claims.push(claim);
    }
    if (description !== undefined && (typeof description !== "string" || description.length > 200)) {
      errors.push(`${where}.description 必须是不超过 200 字的字符串`);
    }
    sources.push({ ns, repo, hosts: claims, description });
  }
  for (let i = 0; i < sources.length; i++) {
    for (let j = i + 1; j < sources.length; j++) {
      for (const a of sources[i].hosts) {
        for (const b of sources[j].hosts) {
          if (claimsOverlap(a, b)) {
            errors.push(`站点认领冲突：${sources[i].ns} 的 ${a} 与 ${sources[j].ns} 的 ${b} 重叠`);
          }
        }
      }
    }
  }
  return { sources, errors };
}

// ===== 规则文件 =====

/**
 * 读取并检查一个规则文件的结构（不含规则内容校验）。
 * 规则仓里的文件只有 `{ rules, tests }`；登记仓库的 sniff-rules.json 还有 `namespace`（必填）与 `hosts`（选填）。
 */
export function parseRuleFile(text, tier, { source = false } = {}) {
  const errors = [];
  let doc;
  try {
    doc = JSON.parse(text);
  } catch (e) {
    return { rules: [], tests: [], errors: [`不是合法 JSON：${e.message}`] };
  }
  if (!isRecord(doc)) return { rules: [], tests: [], errors: ["顶层必须是对象 { rules, tests }"] };
  const allowed = source ? ["rules", "tests", "$schema", "namespace", "hosts"] : ["rules", "tests", "$schema"];
  for (const key of Object.keys(doc)) if (!allowed.includes(key)) errors.push(`未知字段 ${key}`);
  if (source) {
    if (typeof doc.namespace !== "string" || !NS_RE.test(doc.namespace)) errors.push("namespace 缺失或格式不对");
    if (doc.hosts !== undefined && !Array.isArray(doc.hosts)) errors.push("hosts 必须是数组");
  }
  if (!Array.isArray(doc.rules) || doc.rules.length === 0) errors.push("rules 必须是非空数组");
  const tests = doc.tests ?? [];
  if (!Array.isArray(tests)) errors.push("tests 必须是数组");
  else if (tests.length > MAX_TESTS_PER_FILE) errors.push(`tests 超过 ${MAX_TESTS_PER_FILE} 条`);
  const rules = Array.isArray(doc.rules) ? doc.rules : [];
  for (const rule of rules) {
    if (!isRecord(rule)) {
      errors.push("rules 中有非对象元素");
      continue;
    }
    if (rule.tier !== tier) errors.push(`${rule.id ?? "?"}：tier 必须是 ${tier}`);
  }
  for (const [index, test] of (Array.isArray(tests) ? tests : []).entries()) {
    const where = `tests[${index}]`;
    if (!isRecord(test)) {
      errors.push(`${where} 不是对象`);
      continue;
    }
    if (typeof test.name !== "string" || test.name.trim() === "") errors.push(`${where}.name 缺失`);
    if (!TEST_CALLS.has(test.call)) errors.push(`${where}.call 非法：${String(test.call)}`);
    if (!Array.isArray(test.args)) errors.push(`${where}.args 必须是数组`);
    if (!("expect" in test)) errors.push(`${where}.expect 缺失`);
    if (test.options !== undefined && !isRecord(test.options)) errors.push(`${where}.options 必须是对象`);
  }
  return {
    rules,
    tests: Array.isArray(tests) ? tests : [],
    namespace: source ? doc.namespace : undefined,
    hosts: source && Array.isArray(doc.hosts) ? doc.hosts : undefined,
    errors,
  };
}

/**
 * 社区规则的归属检查：id 前缀必须是 `community.<ns>.`；有认领时所有站点模式都要落在认领内；
 * misc 规则不得触碰已被登记仓库认领的站点。
 */
export function checkOwnership(rules, ns, { claims = null, foreignClaims = [] } = {}) {
  const errors = [];
  for (const rule of rules) {
    const id = String(rule.id ?? "?");
    if (namespaceOf(id) !== ns) errors.push(`${id}：id 必须以 community.${ns}. 开头`);
    for (const pattern of rulePatterns(rule)) {
      if (claims !== null && !withinClaims(pattern, claims)) {
        errors.push(`${id}：站点「${pattern}」不在认领范围（${claims.join(", ")}）内`);
      }
      for (const { ns: owner, hosts } of foreignClaims) {
        const parsed = parseHostPattern(pattern);
        if (parsed && hosts.some((claim) => claimsOverlap(parsed.domain, claim))) {
          errors.push(`${id}：站点「${pattern}」已由命名空间 ${owner} 认领，请向其仓库贡献`);
        }
      }
    }
  }
  return errors;
}

/** 吊销源文件 `revocations.json`：{ entries: [{ ruleId, versions, action, reason, ref? }] }。 */
export function parseRevocations(text) {
  const errors = [];
  let doc;
  try {
    doc = JSON.parse(text);
  } catch (e) {
    return { entries: [], errors: [`revocations.json 不是合法 JSON：${e.message}`] };
  }
  if (!isRecord(doc) || !Array.isArray(doc.entries)) {
    return { entries: [], errors: ["revocations.json 必须是 { entries: [] }"] };
  }
  if (doc.entries.length > MAX_REVOCATION_ENTRIES) errors.push("吊销条目过多");
  for (const [index, entry] of doc.entries.entries()) {
    const where = `entries[${index}]`;
    if (!isRecord(entry)) {
      errors.push(`${where} 不是对象`);
      continue;
    }
    if (typeof entry.ruleId !== "string" || !RULE_ID_RE.test(entry.ruleId)) errors.push(`${where}.ruleId 非法`);
    const versions = entry.versions;
    if (versions !== "*" && !(isRecord(versions) && Number.isInteger(versions.max) && versions.max >= 1)) {
      errors.push(`${where}.versions 必须是 "*" 或 { "max": 正整数 }`);
    }
    if (entry.action !== "soft" && entry.action !== "hard") errors.push(`${where}.action 必须是 soft 或 hard`);
    if (typeof entry.reason !== "string" || entry.reason.trim() === "") errors.push(`${where}.reason 缺失`);
    if (entry.ref !== undefined && typeof entry.ref !== "string") errors.push(`${where}.ref 必须是字符串`);
  }
  return { entries: doc.entries, errors };
}

/** 登记仓库快照位置：sources/<ns>/sniff-rules.json + sources/<ns>/pin.json。 */
export function sourcePaths(root, ns) {
  const dir = join(root, "sources", ns);
  return { dir, rules: join(dir, SOURCE_ASSET), pin: join(dir, "pin.json") };
}

function readRegistry(root) {
  const path = join(root, "registry.json");
  return existsSync(path) ? parseRegistry(readFileSync(path, "utf8")) : { sources: [], errors: [] };
}

/**
 * 读取仓库全部源：官方规则、misc 社区规则、各登记仓库的已收录快照、吊销列表。
 * `override` = { ns, text }：用给定内容替换（或新增）某个登记仓库的快照，供收录与作者自检使用。
 */
export function loadSources(root, { override = null, registry: registryOverride = null } = {}) {
  const errors = [];
  const registry = registryOverride ?? readRegistry(root);
  errors.push(...registry.errors);
  const rules = { official: [], community: [] };
  const tests = [];
  const seen = new Map();
  const addRules = (list, rel) => {
    const accepted = [];
    for (const rule of list) {
      const previous = seen.get(rule.id);
      if (previous) {
        errors.push(`${rel}：规则 id ${rule.id} 与 ${previous} 重复`);
        continue;
      }
      seen.set(rule.id, rel);
      accepted.push(rule);
    }
    return accepted;
  };

  for (const [tier, dirName] of [["official", "official"], ["community", "community"]]) {
    const dir = join(root, "rules", dirName);
    if (!existsSync(dir)) continue;
    for (const name of readdirSync(dir).sort()) {
      if (name === "README.md") continue;
      const rel = `rules/${dirName}/${name}`;
      if (!FILE_NAME_RE.test(name)) {
        errors.push(`${rel}：文件名只能含小写字母、数字、点、连字符，并以 .json 结尾`);
        continue;
      }
      const parsed = parseRuleFile(readFileSync(join(dir, name), "utf8"), tier);
      for (const error of parsed.errors) errors.push(`${rel}：${error}`);
      if (parsed.errors.length > 0) continue;
      if (tier === "community") {
        const ownership = checkOwnership(parsed.rules, MISC_NS, { foreignClaims: registry.sources });
        for (const error of ownership) errors.push(`${rel}：${error}`);
        if (ownership.length > 0) continue;
      }
      rules[tier].push(...addRules(parsed.rules, rel));
      for (const test of parsed.tests) tests.push({ ...test, file: rel });
    }
  }

  const registered = new Set(registry.sources.map((s) => s.ns));
  const sourcesDir = join(root, "sources");
  if (existsSync(sourcesDir)) {
    for (const ns of readdirSync(sourcesDir).sort()) {
      if (!registered.has(ns)) errors.push(`sources/${ns}：命名空间未在 registry.json 登记`);
    }
  }
  for (const entry of registry.sources) {
    const paths = sourcePaths(root, entry.ns);
    const rel = `sources/${entry.ns}/${SOURCE_ASSET}`;
    const text = override?.ns === entry.ns ? override.text : existsSync(paths.rules) ? readFileSync(paths.rules, "utf8") : null;
    if (text === null) continue;
    const parsed = parseRuleFile(text, "community", { source: true });
    if (parsed.errors.length === 0 && parsed.namespace !== entry.ns) {
      parsed.errors.push(`namespace「${parsed.namespace}」与登记的「${entry.ns}」不一致`);
    }
    if (parsed.errors.length === 0) parsed.errors.push(...checkOwnership(parsed.rules, entry.ns, { claims: entry.hosts }));
    for (const error of parsed.errors) errors.push(`${rel}：${error}`);
    if (parsed.errors.length > 0) continue;
    rules.community.push(...addRules(parsed.rules, rel));
    for (const test of parsed.tests) tests.push({ ...test, file: rel });
  }

  const revocationPath = join(root, "revocations.json");
  const revocations = existsSync(revocationPath)
    ? parseRevocations(readFileSync(revocationPath, "utf8"))
    : { entries: [], errors: [] };
  errors.push(...revocations.errors);
  return { registry: registry.sources, rules, tests, revocationEntries: revocations.entries, errors };
}

/** 组装规则包载荷（字段顺序固定，序列化结果稳定）。 */
export function makePack(tier, rules, meta) {
  const pack = {
    format: "fluxdown-sniff-pack",
    packId: tier,
    sequence: meta.sequence,
    engine: RULE_ENGINE_VERSION,
    issuedAt: meta.issuedAt,
  };
  if (meta.expiresAt !== undefined) pack.expiresAt = meta.expiresAt;
  pack.rules = rules;
  return pack;
}

export function makeRevocations(entries, meta) {
  return {
    format: "fluxdown-sniff-revocations",
    sequence: meta.sequence,
    issuedAt: meta.issuedAt,
    expiresAt: meta.expiresAt,
    entries,
  };
}

/** 用扩展同款 validatePack 逐条校验；任何一条被剔除都算失败（规则仓不允许静默丢规则）。 */
export function validateRules(tier, rules) {
  const errors = [];
  try {
    const { rejected } = validatePack(makePack(tier, rules, { sequence: 1, issuedAt: new Date(0).toISOString() }), tier);
    for (const r of rejected) errors.push(`${r.id || "?"}：${r.reason}`);
  } catch (e) {
    if (e instanceof PackRejectedError) errors.push(`整包被拒：${e.message}`);
    else throw e;
  }
  return errors;
}

/** 与 bun 的 toMatchObject 一致：对象只比较期望里出现的键，数组逐项且长度相同，其余严格相等。 */
export function matchesExpected(actual, expected) {
  if (Array.isArray(expected)) {
    return (
      Array.isArray(actual) &&
      actual.length === expected.length &&
      expected.every((item, i) => matchesExpected(actual[i], item))
    );
  }
  if (isRecord(expected)) {
    return isRecord(actual) && Object.keys(expected).every((key) => matchesExpected(actual[key], expected[key]));
  }
  return Object.is(actual, expected);
}

/** 用 builtin + 本仓官方 / 全部社区规则编译引擎，逐条执行规则文件里的测试。 */
export function runTests(rules, revocationEntries, tests) {
  const failures = [];
  const meta = { sequence: 1, issuedAt: new Date(0).toISOString() };
  const revocations = makeRevocations(revocationEntries, {
    ...meta,
    expiresAt: new Date(TEST_NOW + EXPIRY_MS).toISOString(),
  });
  for (const test of tests) {
    const engine = compileRules({
      packs: [
        BUILTIN_PACK,
        makePack("official", rules.official, meta),
        makePack("community", rules.community, { ...meta, expiresAt: new Date(TEST_NOW + EXPIRY_MS).toISOString() }),
      ],
      overrides: {},
      revocations,
      options: {
        sniffImages: test.options?.sniffImages ?? false,
        communityEnabled: true,
        now: TEST_NOW,
      },
    });
    let actual;
    try {
      actual = engine[test.call](...test.args);
    } catch (e) {
      failures.push(`${test.file} › ${test.name}：执行出错 ${e.message}`);
      continue;
    }
    const pass =
      test.expect !== null && typeof test.expect === "object"
        ? matchesExpected(actual, test.expect)
        : Object.is(actual, test.expect);
    if (!pass) {
      failures.push(
        `${test.file} › ${test.name}：期望 ${JSON.stringify(test.expect)}，实际 ${JSON.stringify(actual)}`,
      );
    }
  }
  return failures;
}

/** 校验整个仓库：源结构 + 规则内容 + 测试。选项同 loadSources。返回 { sources, errors }。 */
export function checkRepository(root, options = {}) {
  const sources = loadSources(root, options);
  const errors = [...sources.errors];
  if (errors.length === 0) {
    for (const tier of ["official", "community"]) {
      for (const error of validateRules(tier, sources.rules[tier])) errors.push(`[${tier}] ${error}`);
    }
  }
  if (errors.length === 0) errors.push(...runTests(sources.rules, sources.revocationEntries, sources.tests));
  return { sources, errors };
}

/**
 * 已收录规则被修改时 version 必须变大（吊销按版本生效）。返回违规描述。
 */
export function versionRegressions(previousRules, nextRules) {
  const errors = [];
  const before = new Map(previousRules.map((rule) => [rule.id, rule]));
  for (const rule of nextRules) {
    const old = before.get(rule.id);
    if (!old || JSON.stringify(old) === JSON.stringify(rule)) continue;
    if (!(rule.version > old.version)) {
      errors.push(`${rule.id}：内容有改动但 version 没有变大（已收录 ${old.version}，新 ${rule.version}）`);
    }
  }
  return errors;
}

/** 解出已发布信封里的载荷；文件不存在返回 null。 */
export function readPublished(path) {
  if (!existsSync(path)) return null;
  const envelope = JSON.parse(readFileSync(path, "utf8"));
  return JSON.parse(Buffer.from(envelope.payload, "base64").toString("utf8"));
}

/**
 * 决定一份文档是否需要重新签发：内容变化、从未发布、或有效期剩余不足 RENEW_WITHIN_MS。
 * 重新签发时 sequence 加一（agent 只接受更大的 sequence）。返回 null 表示沿用已发布版本。
 */
export function nextMeta({ previous, body, bodyOf, expires, now }) {
  const renew =
    expires &&
    previous !== null &&
    !(Date.parse(previous.expiresAt) - now > RENEW_WITHIN_MS);
  const changed = previous === null || JSON.stringify(bodyOf(previous)) !== JSON.stringify(body);
  if (!changed && !renew) return null;
  const meta = {
    sequence: previous === null ? 1 : previous.sequence + 1,
    issuedAt: new Date(now).toISOString(),
  };
  if (expires) meta.expiresAt = new Date(now + EXPIRY_MS).toISOString();
  return meta;
}

/** 载荷大小上限（字节），与 agent 一致。 */
export function payloadLimit(kind) {
  return kind === "revocations" ? MAX_REVOCATION_PAYLOAD_BYTES : MAX_PACK_PAYLOAD_BYTES;
}

/**
 * 签名并封装为信封（与 FluxDown scripts/sniff-rules/sign.ts、agent verify.rs 同格式）。
 * 签名后用 keys.json 中同 keyId 的公钥回验，防止 CI 配错私钥发出客户端不认的包。
 */
export function signEnvelope(payloadBytes, { pem, keyId, trusted }) {
  const publicRaw = trusted[keyId];
  if (typeof publicRaw !== "string") throw new Error(`keys.json 中没有 keyId ${keyId}`);
  const privateKey = createPrivateKey(pem);
  const sig = sign(null, payloadBytes, privateKey);
  const publicKey = createPublicKey({
    key: { kty: "OKP", crv: "Ed25519", x: Buffer.from(publicRaw, "base64").toString("base64url") },
    format: "jwk",
  });
  if (!verify(null, payloadBytes, publicKey, sig)) {
    throw new Error(`签名私钥与 keys.json 中 ${keyId} 的公钥不匹配`);
  }
  return JSON.stringify({
    payload: payloadBytes.toString("base64"),
    signatures: [{ keyId, sig: sig.toString("base64") }],
  });
}
