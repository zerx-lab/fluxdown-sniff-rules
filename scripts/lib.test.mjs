import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createPublicKey, generateKeyPairSync, verify } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, test } from "node:test";
import {
  EXPIRY_MS,
  RENEW_WITHIN_MS,
  checkRepository,
  loadSources,
  matchesExpected,
  nextMeta,
  parseRevocations,
  parseRuleFile,
  runTests,
  signEnvelope,
  validateRules,
} from "./lib.mjs";
import { scratchRepo } from "./test-support.mjs";

const siteRule = (overrides = {}) => ({
  id: "community.misc.video",
  version: 1,
  tier: "community",
  stage: "response",
  match: { host: ["example.com"], ext: ["xyz"] },
  action: { kind: "resource", type: "video" },
  ...overrides,
});

describe("规则文件结构", () => {
  test("tier 必须与目录一致，未知字段与非法测试被指出", () => {
    const text = JSON.stringify({
      rules: [siteRule({ tier: "official" })],
      tests: [{ name: "x", call: "eval", args: [], expect: 1 }],
      extra: true,
    });
    const { errors } = parseRuleFile(text, "community");
    assert.ok(errors.some((e) => e.includes("tier 必须是 community")));
    assert.ok(errors.some((e) => e.includes("未知字段 extra")));
    assert.ok(errors.some((e) => e.includes("call 非法")));
  });

  test("空规则与非法 JSON 被拒", () => {
    assert.ok(parseRuleFile('{"rules": []}', "community").errors.length > 0);
    assert.ok(parseRuleFile("{", "community").errors[0].startsWith("不是合法 JSON"));
  });

  test("吊销条目逐字段检查", () => {
    const { errors } = parseRevocations(
      JSON.stringify({ entries: [{ ruleId: "bad id", versions: { max: 0 }, action: "kill", reason: "" }] }),
    );
    assert.equal(errors.length, 4);
    assert.deepEqual(
      parseRevocations(
        JSON.stringify({ entries: [{ ruleId: "community.a.b", versions: "*", action: "hard", reason: "误判" }] }),
      ).errors,
      [],
    );
  });

  test("跨文件重复的规则 id 报错", () => {
    const dir = scratchRepo();
    const file = JSON.stringify({ rules: [siteRule()] });
    writeFileSync(join(dir, "rules/community/a.json"), file);
    writeFileSync(join(dir, "rules/community/b.json"), file);
    const { errors } = loadSources(dir);
    assert.ok(errors.some((e) => e.includes("rules/community/b.json") && e.includes("重复")));
  });
});

describe("规则内容校验（扩展同款 validatePack）", () => {
  test("社区规则必须限定站点，且不能用 preempt", () => {
    assert.deepEqual(validateRules("community", [siteRule()]), []);
    assert.equal(validateRules("community", [siteRule({ match: { ext: ["xyz"] } })]).length, 1);
    const preempt = siteRule({
      stage: "body",
      match: { host: ["example.com"] },
      action: { kind: "extract", fields: { u: "u" }, emit: { mode: "preempt", url: "${u}" } },
    });
    assert.match(validateRules("community", [preempt])[0], /preempt/);
  });
});

describe("规则测试", () => {
  test("toMatchObject 语义：对象子集、数组等长逐项、标量严格相等", () => {
    assert.ok(matchesExpected({ a: 1, b: { c: 2, d: 3 } }, { b: { c: 2 } }));
    assert.ok(!matchesExpected([{ a: 1 }, { a: 2 }], [{ a: 1 }]));
    assert.ok(matchesExpected([{ a: 1, x: 0 }], [{ a: 1 }]));
    assert.ok(!matchesExpected("1", 1));
    assert.ok(!matchesExpected(null, {}));
  });

  test("期望不符时报告文件与用例名，相符时无失败", () => {
    const rules = { official: [], community: [siteRule()] };
    const passing = {
      file: "f.json",
      name: "命中",
      call: "classifyResponse",
      args: [{ url: "https://cdn.example.com/a.xyz", pageUrl: "", size: 0, attachment: false }],
      expect: { decision: "resource", type: "video", rule: { id: "community.misc.video" } },
    };
    assert.deepEqual(runTests(rules, [], [passing]), []);
    const failing = { ...passing, name: "写错期望", expect: { decision: "ignore" } };
    const failures = runTests(rules, [], [failing]);
    assert.equal(failures.length, 1);
    assert.match(failures[0], /^f\.json › 写错期望：/);
  });

  test("吊销的规则在测试中同样失效", () => {
    const rules = { official: [], community: [siteRule()] };
    const call = {
      file: "f.json",
      name: "被吊销后不再命中",
      call: "classifyResponse",
      args: [{ url: "https://cdn.example.com/a.xyz", pageUrl: "", size: 0, attachment: false }],
      expect: { decision: "none" },
    };
    const revoked = [{ ruleId: "community.misc.video", versions: "*", action: "hard", reason: "x" }];
    assert.deepEqual(runTests(rules, revoked, [call]), []);
  });

  test("仓库自带的官方规则全部通过", () => {
    assert.deepEqual(checkRepository(scratchRepo()).errors, []);
  });

  test("已下架命名空间的残留快照不参与打包也不报错", () => {
    const dir = scratchRepo();
    mkdirSync(join(dir, "sources/gone"), { recursive: true });
    writeFileSync(join(dir, "sources/gone/sniff-rules.json"), "{}");
    const { errors, sources } = checkRepository(dir);
    assert.deepEqual(errors, []);
    assert.equal(sources.rules.community.length, 0);
  });
});

describe("签发判定", () => {
  const now = Date.parse("2026-06-01T00:00:00Z");
  const bodyOf = (doc) => doc.rules;
  const published = (rules, expiresInMs) => ({
    sequence: 7,
    issuedAt: "2026-05-01T00:00:00Z",
    expiresAt: new Date(now + expiresInMs).toISOString(),
    rules,
  });

  test("首次发布 sequence 为 1", () => {
    const meta = nextMeta({ previous: null, body: [], bodyOf, expires: false, now });
    assert.equal(meta.sequence, 1);
    assert.equal(meta.expiresAt, undefined);
  });

  test("内容不变且有效期充足时沿用", () => {
    const previous = published([1], RENEW_WITHIN_MS + 1);
    assert.equal(nextMeta({ previous, body: [1], bodyOf, expires: true, now }), null);
  });

  test("内容变化或有效期将尽时 sequence 加一并重置有效期", () => {
    const changed = nextMeta({ previous: published([1], EXPIRY_MS), body: [2], bodyOf, expires: true, now });
    assert.equal(changed.sequence, 8);
    assert.equal(changed.expiresAt, new Date(now + EXPIRY_MS).toISOString());
    const renewed = nextMeta({ previous: published([1], RENEW_WITHIN_MS), body: [1], bodyOf, expires: true, now });
    assert.equal(renewed.sequence, 8);
  });

  test("官方包没有有效期，内容不变就永不重签", () => {
    const previous = { sequence: 3, issuedAt: "2020-01-01T00:00:00Z", rules: [1] };
    assert.equal(nextMeta({ previous, body: [1], bodyOf, expires: false, now }), null);
  });
});

describe("签名", () => {
  const pair = () => generateKeyPairSync("ed25519");
  const rawPublic = (publicKey) => Buffer.from(publicKey.export({ format: "jwk" }).x, "base64url").toString("base64");

  test("信封可用公钥验证", () => {
    const { publicKey, privateKey } = pair();
    const payload = Buffer.from('{"a":1}');
    const envelope = JSON.parse(
      signEnvelope(payload, {
        pem: privateKey.export({ format: "pem", type: "pkcs8" }),
        keyId: "k1",
        trusted: { k1: rawPublic(publicKey) },
      }),
    );
    assert.equal(Buffer.from(envelope.payload, "base64").toString(), '{"a":1}');
    assert.equal(envelope.signatures[0].keyId, "k1");
    assert.ok(verify(null, payload, publicKey, Buffer.from(envelope.signatures[0].sig, "base64")));
  });

  test("私钥与登记的公钥不符时拒绝签发", () => {
    const signer = pair();
    const other = pair();
    assert.throws(
      () =>
        signEnvelope(Buffer.from("x"), {
          pem: signer.privateKey.export({ format: "pem", type: "pkcs8" }),
          keyId: "k1",
          trusted: { k1: rawPublic(other.publicKey) },
        }),
      /不匹配/,
    );
  });
});

describe("build.mjs 端到端", () => {
  test("签发三份文档，再次运行无变化，规则变化后只重签变化的文档", () => {
    const dir = scratchRepo();
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const raw = Buffer.from(publicKey.export({ format: "jwk" }).x, "base64url").toString("base64");
    writeFileSync(join(dir, "keys.json"), JSON.stringify({ release: { "test-key": raw } }));
    const env = {
      ...process.env,
      SNIFF_SIGNING_KEY: privateKey.export({ format: "pem", type: "pkcs8" }),
      SNIFF_SIGNING_KEY_ID: "test-key",
    };
    const build = (now) =>
      execFileSync("node", [join(dir, "scripts/build.mjs"), "--sign", "--root", dir, "--now", now], {
        env,
        encoding: "utf8",
      });
    const payloadOf = (kind) => {
      const envelope = JSON.parse(readFileSync(join(dir, "dist", `${kind}.json`), "utf8"));
      const bytes = Buffer.from(envelope.payload, "base64");
      const pub = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: Buffer.from(raw, "base64").toString("base64url") }, format: "jwk" });
      assert.ok(verify(null, bytes, pub, Buffer.from(envelope.signatures[0].sig, "base64")));
      return JSON.parse(bytes.toString("utf8"));
    };

    build("2026-06-01T00:00:00Z");
    const official = payloadOf("official");
    assert.equal(official.packId, "official");
    assert.equal(official.sequence, 1);
    assert.ok(official.rules.length > 0);
    assert.equal(payloadOf("community").rules.length, 0);
    assert.equal(payloadOf("revocations").expiresAt, "2026-07-01T00:00:00.000Z");

    assert.match(build("2026-06-02T00:00:00Z"), /没有需要签发的文档/);

    writeFileSync(
      join(dir, "rules/community/example.com.json"),
      JSON.stringify({ rules: [siteRule()] }),
    );
    build("2026-06-03T00:00:00Z");
    assert.equal(payloadOf("official").sequence, 1);
    assert.equal(payloadOf("community").sequence, 2);
    assert.equal(payloadOf("community").rules[0].id, "community.misc.video");
    assert.equal(payloadOf("revocations").sequence, 1);

    // 吊销列表有效期剩余不足 14 天时由定时任务续签。
    build("2026-06-20T00:00:00Z");
    assert.equal(payloadOf("revocations").sequence, 2);
    assert.equal(payloadOf("community").sequence, 3);
  });

  test("校验失败时不签发", () => {
    const dir = scratchRepo();
    writeFileSync(join(dir, "rules/community/bad.json"), JSON.stringify({ rules: [siteRule({ match: {} })] }));
    assert.throws(
      () => execFileSync("node", [join(dir, "scripts/build.mjs"), "--check", "--root", dir], { stdio: "pipe" }),
      (e) => String(e.stderr).includes("社区规则必须限定 host 或 pageHost"),
    );
  });
});
