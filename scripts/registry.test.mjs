import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, test } from "node:test";
import { checkRegistryChange } from "./check-registry.mjs";
import { checkSource } from "./check-source.mjs";
import { checkOwnership, checkRepository, parseRegistry, versionRegressions } from "./lib.mjs";
import { stageAll, stageOne, summary } from "./stage.mjs";
import { scratchRepo } from "./test-support.mjs";

const ALICE = { ns: "alice", repo: "alice/my-rules", hosts: ["example.com", "example-cdn.net"] };

const aliceRule = (overrides = {}) => ({
  id: "community.alice.video",
  version: 1,
  tier: "community",
  title: "Example 视频",
  stage: "response",
  match: { host: ["example.com"], ext: ["xyz"] },
  action: { kind: "resource", type: "video" },
  ...overrides,
});

const sourceText = (rules = [aliceRule()], extra = {}) =>
  JSON.stringify({
    namespace: "alice",
    rules,
    tests: [
      {
        name: "识别 xyz 视频",
        call: "classifyResponse",
        args: [{ url: "https://cdn.example.com/a.xyz", pageUrl: "", size: 0, attachment: false }],
        expect: { decision: "resource", rule: { id: rules[0].id } },
      },
    ],
    ...extra,
  });

const release = (text, tag = "v1.0.0", publishedAt = "2026-06-01T00:00:00Z") => ({
  ok: true,
  tag,
  publishedAt,
  url: `https://github.com/alice/my-rules/releases/download/${tag}/sniff-rules.json`,
  sha256: createHash("sha256").update(text).digest("hex"),
  text,
});

describe("registry.json", () => {
  test("合法登记通过；命名空间格式、保留字、重复、仓库重复、认领冲突都被指出", () => {
    assert.deepEqual(parseRegistry(JSON.stringify({ sources: [ALICE] })).errors, []);
    const { errors } = parseRegistry(
      JSON.stringify({
        sources: [
          ALICE,
          { ns: "misc", repo: "x/y", hosts: ["a.org"] },
          { ns: "Bad_NS", repo: "x/z", hosts: ["b.org"] },
          { ns: "alice", repo: "x/w", hosts: ["c.org"] },
          { ns: "bob", repo: "Alice/my-rules", hosts: ["d.org"] },
          { ns: "carol", repo: "carol/r", hosts: ["video.example.com"] },
          { ns: "dave", repo: "dave/r", hosts: ["*.e.org", "=f.org", "com"] },
        ],
      }),
    );
    for (const expected of ["保留字", "只能含小写字母", "「alice」重复", "已被其它命名空间登记", "站点认领冲突", "*.e.org", "=f.org", "「com」"]) {
      assert.ok(errors.some((e) => e.includes(expected)), `缺少：${expected}\n${errors.join("\n")}`);
    }
  });
});

describe("归属检查", () => {
  test("id 前缀与站点认领", () => {
    const claims = ALICE.hosts;
    assert.deepEqual(checkOwnership([aliceRule()], "alice", { claims }), []);
    assert.deepEqual(checkOwnership([aliceRule({ match: { host: ["=dl.example-cdn.net"] } })], "alice", { claims }), []);
    assert.match(checkOwnership([aliceRule({ id: "community.bob.x" })], "alice", { claims })[0], /community\.alice\./);
    assert.match(checkOwnership([aliceRule({ match: { host: ["other.org"] } })], "alice", { claims })[0], /不在认领范围/);
    assert.match(
      checkOwnership([aliceRule({ exclude: [{ pageHost: ["other.org"] }] })], "alice", { claims })[0],
      /other\.org/,
    );
  });

  test("misc 规则不得触碰已被认领的站点", () => {
    const dir = scratchRepo({ registry: [ALICE] });
    writeFileSync(
      join(dir, "rules/community/example.com.json"),
      JSON.stringify({ rules: [aliceRule({ id: "community.misc.v", match: { host: ["www.example.com"], ext: ["xyz"] } })] }),
    );
    assert.ok(checkRepository(dir).errors.some((e) => e.includes("已由命名空间 alice 认领")));
  });

  test("修改已收录规则必须提升 version", () => {
    assert.deepEqual(versionRegressions([aliceRule()], [aliceRule({ version: 2, title: "新" })]), []);
    assert.deepEqual(versionRegressions([aliceRule()], [aliceRule()]), []);
    assert.equal(versionRegressions([aliceRule()], [aliceRule({ title: "新" })]).length, 1);
  });
});

describe("收录", () => {
  test("首次收录写入快照与 pin；同一 Release 再次收录无变化", () => {
    const dir = scratchRepo({ registry: [ALICE] });
    const text = sourceText();
    assert.deepEqual(stageOne(dir, ALICE, release(text)), { status: "updated" });
    assert.equal(readFileSync(join(dir, "sources/alice/sniff-rules.json"), "utf8"), text);
    const pin = JSON.parse(readFileSync(join(dir, "sources/alice/pin.json"), "utf8"));
    assert.equal(pin.tag, "v1.0.0");
    assert.equal(stageOne(dir, ALICE, release(text)).status, "unchanged");
    assert.deepEqual(checkRepository(dir).errors, []);
  });

  test("旧 Release 附件被替换、Release 不更新、改规则不升版本、越界站点都拒收并保留旧版本", () => {
    const dir = scratchRepo({ registry: [ALICE] });
    const text = sourceText();
    stageOne(dir, ALICE, release(text));
    const swapped = { ...release(sourceText([aliceRule({ title: "换" })])), tag: "v1.0.0" };
    assert.match(stageOne(dir, ALICE, swapped).errors[0], /附件被替换/);
    assert.match(stageOne(dir, ALICE, release(sourceText([aliceRule({ version: 2 })]), "v0.9.0", "2026-05-01T00:00:00Z")).errors[0], /不比已收录/);
    assert.match(stageOne(dir, ALICE, release(sourceText([aliceRule({ title: "改" })]), "v1.1.0", "2026-07-01T00:00:00Z")).errors[0], /version 没有变大/);
    const outside = stageOne(dir, ALICE, release(sourceText([aliceRule({ version: 2, match: { host: ["evil.test"], ext: ["xyz"] } })]), "v1.2.0", "2026-07-02T00:00:00Z"));
    assert.ok(outside.errors.some((e) => e.includes("不在认领范围")));
    assert.equal(readFileSync(join(dir, "sources/alice/sniff-rules.json"), "utf8"), text);
  });

  test("规则自带测试失败、namespace 不符时拒收", () => {
    const dir = scratchRepo({ registry: [ALICE] });
    const failing = JSON.parse(sourceText());
    failing.tests[0].expect = { decision: "ignore" };
    assert.ok(stageOne(dir, ALICE, release(JSON.stringify(failing))).errors.some((e) => e.includes("识别 xyz 视频")));
    assert.ok(stageOne(dir, ALICE, release(sourceText(undefined, { namespace: "bob" }))).errors.some((e) => e.includes("namespace")));
    assert.equal(existsSync(join(dir, "sources/alice")), false);
  });

  test("stageAll：成功、失败分开记录；登记表删除的命名空间被下架", async () => {
    const bob = { ns: "bob", repo: "bob/r", hosts: ["bob.example.org"] };
    const dir = scratchRepo({ registry: [ALICE, bob] });
    mkdirSync(join(dir, "sources/gone"), { recursive: true });
    writeFileSync(join(dir, "sources/gone/sniff-rules.json"), "{}");
    const results = await stageAll(dir, {
      fetchRelease: async (repo) => (repo === ALICE.repo ? release(sourceText()) : { ok: false, error: "没有 Release" }),
    });
    assert.deepEqual(results.updated, [{ ns: "alice", tag: "v1.0.0" }]);
    assert.deepEqual(results.removed, ["gone"]);
    assert.deepEqual(results.failures, { bob: { repo: "bob/r", errors: ["没有 Release"] } });
    assert.deepEqual(results.healthy, ["alice"]);
    assert.equal(summary(results), "stage: alice v1.0.0, remove gone");
    assert.equal(existsSync(join(dir, "sources/gone")), false);
    assert.deepEqual(checkRepository(dir).errors, []);
  });
});

describe("登记 PR 检查", () => {
  test("新增登记：拉取 Release 跑完整检查并列出规则", async () => {
    const dir = scratchRepo();
    const head = JSON.stringify({ sources: [ALICE] });
    const result = await checkRegistryChange(dir, head, {
      author: "alice",
      files: ["registry.json"],
      fetchRelease: async () => release(sourceText()),
    });
    assert.equal(result.ok, true, result.comment);
    assert.match(result.comment, /community\.alice\.video/);
  });

  test("改了 registry.json 以外的文件、Release 不合格、非 owner 提交分别报告", async () => {
    const dir = scratchRepo();
    const head = JSON.stringify({ sources: [ALICE] });
    const result = await checkRegistryChange(dir, head, {
      author: "mallory",
      files: ["registry.json", "rules/official/x.json"],
      fetchRelease: async () => release(sourceText([aliceRule({ match: { host: ["evil.test"], ext: ["xyz"] } })])),
    });
    assert.equal(result.ok, false);
    assert.match(result.comment, /只能修改 registry\.json/);
    assert.match(result.comment, /不在认领范围/);
    assert.match(result.comment, /不是仓库 alice\/my-rules 的 owner/);
  });
});

describe("作者自检", () => {
  test("未登记：按文件 hosts 检查；已登记：按登记认领并核对仓库", () => {
    const fresh = scratchRepo();
    assert.equal(checkSource(fresh, sourceText(undefined, { hosts: ALICE.hosts })).ok, true);
    assert.match(checkSource(fresh, sourceText()).errors[0], /hosts/);
    const registered = scratchRepo({ registry: [ALICE] });
    assert.equal(checkSource(registered, sourceText(), { repo: "alice/my-rules" }).ok, true);
    assert.match(checkSource(registered, sourceText(), { repo: "eve/fork" }).errors[0], /已由 alice\/my-rules 登记/);
  });
});
