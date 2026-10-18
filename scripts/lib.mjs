// 规则仓核心：读取规则源 → 校验 → 跑规则自带测试 → 组装规则包 / 吊销列表 → 签名。
// 校验与求值用 vendor/fluxdown-sniff-rules.mjs（由 FluxDown 仓库从扩展源码打包），与扩展行为一致。
import { createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import {
  BUILTIN_PACK,
  PackRejectedError,
  RULE_ENGINE_VERSION,
  compileRules,
  validatePack,
} from "../vendor/fluxdown-sniff-rules.mjs";

export const PACK_TIERS = ["official", "community"];
/** 规则文件名：小写字母 / 数字开头，只含小写字母、数字、点、连字符。 */
export const FILE_NAME_RE = /^[a-z0-9][a-z0-9.-]{0,79}\.json$/;
const RULE_ID_RE = /^(builtin|official|plugin|community|local)\.[a-z0-9][a-z0-9._-]{1,62}$/;
const DAY_MS = 24 * 60 * 60 * 1000;
/** 社区包与吊销列表的有效期；剩余不足 RENEW_WITHIN 时重新签发。 */
export const EXPIRY_MS = 30 * DAY_MS;
export const RENEW_WITHIN_MS = 14 * DAY_MS;
/** 与 FluxDown agent `sniff_rules/verify.rs` 的上限一致。 */
const MAX_PACK_PAYLOAD_BYTES = 400 * 1024;
const MAX_REVOCATION_PAYLOAD_BYTES = 64 * 1024;
const MAX_REVOCATION_ENTRIES = 5000;
const MAX_TESTS_PER_FILE = 200;
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

/**
 * 读取并检查一个规则文件的结构（不含规则内容校验）。
 * 返回 { rules, tests, errors }；errors 非空时其余字段不可信。
 */
export function parseRuleFile(text, tier) {
  const errors = [];
  let doc;
  try {
    doc = JSON.parse(text);
  } catch (e) {
    return { rules: [], tests: [], errors: [`不是合法 JSON：${e.message}`] };
  }
  if (!isRecord(doc)) return { rules: [], tests: [], errors: ["顶层必须是对象 { rules, tests }"] };
  for (const key of Object.keys(doc)) {
    if (key !== "rules" && key !== "tests" && key !== "$schema") errors.push(`未知字段 ${key}`);
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
    if (rule.tier !== tier) errors.push(`${rule.id ?? "?"}：tier 必须是 ${tier}（由所在目录决定）`);
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
  return { rules, tests: Array.isArray(tests) ? tests : [], errors };
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
    if (
      versions !== "*" &&
      !(isRecord(versions) && Number.isInteger(versions.max) && versions.max >= 1)
    ) {
      errors.push(`${where}.versions 必须是 "*" 或 { "max": 正整数 }`);
    }
    if (entry.action !== "soft" && entry.action !== "hard") errors.push(`${where}.action 必须是 soft 或 hard`);
    if (typeof entry.reason !== "string" || entry.reason.trim() === "") errors.push(`${where}.reason 缺失`);
    if (entry.ref !== undefined && typeof entry.ref !== "string") errors.push(`${where}.ref 必须是字符串`);
  }
  return { entries: doc.entries, errors };
}

/** 读取仓库全部源文件；返回规则、测试与按文件归类的错误。 */
export function loadSources(root) {
  const errors = [];
  const rules = { official: [], community: [] };
  const tests = [];
  const seen = new Map();
  for (const tier of PACK_TIERS) {
    const dir = join(root, "rules", tier);
    if (!existsSync(dir)) continue;
    for (const name of readdirSync(dir).sort()) {
      if (name === "README.md") continue;
      const rel = `rules/${tier}/${name}`;
      if (!FILE_NAME_RE.test(name)) {
        errors.push(`${rel}：文件名只能含小写字母、数字、点、连字符，并以 .json 结尾`);
        continue;
      }
      const parsed = parseRuleFile(readFileSync(join(dir, name), "utf8"), tier);
      for (const error of parsed.errors) errors.push(`${rel}：${error}`);
      if (parsed.errors.length > 0) continue;
      for (const rule of parsed.rules) {
        const previous = seen.get(rule.id);
        if (previous) {
          errors.push(`${rel}：规则 id ${rule.id} 与 ${previous} 重复`);
          continue;
        }
        seen.set(rule.id, rel);
        rules[tier].push(rule);
      }
      for (const test of parsed.tests) tests.push({ ...test, file: rel });
    }
  }
  const revocationPath = join(root, "revocations.json");
  const revocations = existsSync(revocationPath)
    ? parseRevocations(readFileSync(revocationPath, "utf8"))
    : { entries: [], errors: [] };
  errors.push(...revocations.errors);
  return { rules, tests, revocationEntries: revocations.entries, errors };
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

/** 用 builtin + 本仓官方 / 社区规则编译引擎，逐条执行规则文件里的测试。 */
export function runTests(rules, revocationEntries, tests) {
  const failures = [];
  const meta = { sequence: 1, issuedAt: new Date(0).toISOString() };
  const revocations = makeRevocations(revocationEntries, {
    ...meta,
    expiresAt: new Date(TEST_NOW + EXPIRY_MS).toISOString(),
  });
  for (const test of tests) {
    const engine = compileRules({
      packs: [BUILTIN_PACK, makePack("official", rules.official, meta), makePack("community", rules.community, meta)],
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

/** 校验整个仓库：源结构 + 规则内容 + 测试。返回 { sources, errors }。 */
export function checkRepository(root) {
  const sources = loadSources(root);
  const errors = [...sources.errors];
  if (errors.length === 0) {
    for (const tier of PACK_TIERS) {
      for (const error of validateRules(tier, sources.rules[tier])) errors.push(`[${tier}] ${error}`);
    }
  }
  if (errors.length === 0) errors.push(...runTests(sources.rules, sources.revocationEntries, sources.tests));
  return { sources, errors };
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
