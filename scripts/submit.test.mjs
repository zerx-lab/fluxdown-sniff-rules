import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, test } from "node:test";
import { FIELDS, MAINTAINER_LABEL, fileSlug, mergeRuleFile, parseIssueForm, parseSamples, processSubmission, toCommunityRules } from "./submit.mjs";
import { ROOT, scratchRepo } from "./test-support.mjs";

const localRule = {
  id: "local.example-video",
  version: 3,
  tier: "local",
  title: "Example 视频",
  stage: "response",
  match: { host: ["=www.example.com"], ext: ["xyz"] },
  action: { kind: "resource", type: "video" },
};

/** 按 GitHub Issue 表单的渲染格式拼出正文。 */
function issueBody({ rule, page = "https://www.example.com/watch/1", samples = "", tests = "", notes = "" }) {
  const section = (label, value, fence) =>
    `### ${label}\n\n${value === "" ? "_No response_" : fence ? `\`\`\`json\n${value}\n\`\`\`` : value}`;
  return [
    section(FIELDS.rule, rule, true),
    section(FIELDS.page, page),
    section(FIELDS.samples, samples),
    section(FIELDS.tests, tests, true),
    section(FIELDS.notes, notes),
    "### 确认 / Confirm\n\n- [X] 我已验证",
  ].join("\n\n");
}

const issue = (body) => ({ number: 42, title: "[规则] example", body, user: { login: "alice", id: 7 } });

describe("Issue 表单解析", () => {
  test("按标题分段、去掉代码围栏、_No response_ 视为空", () => {
    const fields = parseIssueForm(issueBody({ rule: '{"a": 1}' }).replace(/\n/g, "\r\n"));
    assert.equal(fields[FIELDS.rule], '{"a": 1}');
    assert.equal(fields[FIELDS.page], "https://www.example.com/watch/1");
    assert.equal(fields[FIELDS.tests], "");
  });

  test("字段标题与 Issue 模板的 label 一致", () => {
    const template = readFileSync(join(ROOT, ".github/ISSUE_TEMPLATE/community-rule.yml"), "utf8");
    for (const label of Object.values(FIELDS)) {
      assert.ok(template.includes(`label: ${label}\n`), `模板缺少 label: ${label}`);
    }
  });
});

describe("规则转换", () => {
  test("local.* 改写为 community.*，其它层级拒绝", () => {
    const { rules, errors } = toCommunityRules([localRule, { ...localRule, id: "official.x.y", tier: "official" }]);
    assert.equal(rules.length, 1);
    assert.equal(rules[0].id, "community.misc.example-video");
    assert.equal(rules[0].tier, "community");
    assert.match(errors[0], /official\.x\.y/);
  });

  test("接受导出的规则文件并带上其中的测试", () => {
    const { rules, tests } = toCommunityRules({ rules: [localRule], tests: [{ name: "t" }] });
    assert.equal(rules.length, 1);
    assert.deepEqual(tests, [{ name: "t" }]);
  });

  test("文件名取第一条规则的站点", () => {
    assert.equal(fileSlug(localRule), "example.com");
    assert.equal(fileSlug({ match: { pageHost: ["Video.Example.org"] } }), "video.example.org");
    assert.equal(fileSlug({ match: {} }), null);
  });

  test("合并：同内容保留版本，改动后版本递增，新规则追加", () => {
    const existing = { rules: [{ ...localRule, id: "community.a", version: 2 }] };
    const same = mergeRuleFile(existing, [{ ...localRule, id: "community.a", version: 1 }], []);
    assert.equal(same.rules[0].version, 2);
    const changed = mergeRuleFile(existing, [{ ...localRule, id: "community.a", version: 1, title: "新" }], []);
    assert.equal(changed.rules[0].version, 3);
    const added = mergeRuleFile(existing, [{ ...localRule, id: "community.b" }], [{ name: "t" }]);
    assert.deepEqual(added.rules.map((r) => r.id), ["community.a", "community.b"]);
    assert.deepEqual(added.tests, [{ name: "t" }]);
  });
});

describe("提交处理", () => {
  test("合格的本地规则写入 rules/community/<站点>.json 并通过整库校验", () => {
    const dir = scratchRepo();
    const tests = JSON.stringify([
      {
        name: "识别 xyz 视频",
        call: "classifyResponse",
        args: [{ url: "https://www.example.com/v/a.xyz", pageUrl: "", size: 0, attachment: false }],
        expect: { decision: "resource", type: "video" },
      },
    ]);
    const result = processSubmission({ root: dir, issue: issue(issueBody({ rule: JSON.stringify(localRule), tests })) });
    assert.equal(result.ok, true, result.errors.join("\n"));
    assert.equal(result.file, "rules/community/example.com.json");
    assert.deepEqual(result.warnings, []);
    const written = JSON.parse(readFileSync(join(dir, result.file), "utf8"));
    assert.equal(written.rules[0].id, "community.misc.example-video");
    assert.equal(written.rules[0].version, 3);
    assert.equal(written.tests.length, 1);
  });

  test("规则测试失败时不留下文件并返回失败原因", () => {
    const dir = scratchRepo();
    const tests = JSON.stringify([
      {
        name: "期望写错",
        call: "classifyResponse",
        args: [{ url: "https://www.example.com/v/a.xyz", pageUrl: "", size: 0, attachment: false }],
        expect: { decision: "ignore" },
      },
    ]);
    const result = processSubmission({ root: dir, issue: issue(issueBody({ rule: JSON.stringify(localRule), tests })) });
    assert.equal(result.ok, false);
    assert.ok(result.errors.some((e) => e.includes("期望写错")));
    assert.equal(existsSync(join(dir, "rules/community/example.com.json")), false);
  });

  test("更新已有站点文件失败时恢复原内容", () => {
    const dir = scratchRepo();
    const path = join(dir, "rules/community/example.com.json");
    const original = `${JSON.stringify({ rules: [{ ...localRule, id: "community.misc.keep", tier: "community" }] }, null, 2)}\n`;
    writeFileSync(path, original);
    const broken = { ...localRule, action: { kind: "resource", type: "nope" } };
    const result = processSubmission({ root: dir, issue: issue(issueBody({ rule: JSON.stringify(broken) })) });
    assert.equal(result.ok, false);
    assert.equal(readFileSync(path, "utf8"), original);
  });

  test("未限定站点、JSON 错误、示例页面非法分别给出原因", () => {
    const dir = scratchRepo();
    const run = (body) => processSubmission({ root: dir, issue: issue(body) });
    const unscoped = run(issueBody({ rule: JSON.stringify({ ...localRule, match: { ext: ["xyz"] } }) }));
    assert.match(unscoped.errors[0], /限定站点/);
    assert.match(run(issueBody({ rule: "{oops" })).errors[0], /解析失败/);
    assert.match(run(issueBody({ rule: JSON.stringify(localRule), page: "example.com" })).errors[0], /http\(s\)/);
  });

  test("示例页面不在规则站点内时只给提醒", () => {
    const dir = scratchRepo();
    const result = processSubmission({
      root: dir,
      issue: issue(issueBody({ rule: JSON.stringify(localRule), page: "https://other.org/" })),
    });
    assert.equal(result.ok, true);
    assert.match(result.warnings[0], /other\.org/);
  });

  test("命令行输出 result.json / comment.md / pr.md", () => {
    const dir = scratchRepo();
    const event = join(dir, "event.json");
    writeFileSync(event, JSON.stringify({ issue: issue(issueBody({ rule: JSON.stringify(localRule) })) }));
    const out = join(dir, "out");
    execFileSync("node", [join(dir, "scripts/submit.mjs"), "--event", event, "--out", out, "--root", dir]);
    const result = JSON.parse(readFileSync(join(out, "result.json"), "utf8"));
    assert.equal(result.ok, true);
    assert.equal(result.prTitle, "community: [规则] example");
    assert.match(result.commitMessage, /Co-authored-by: alice <7\+alice@users\.noreply\.github\.com>/);
    assert.match(readFileSync(join(out, "pr.md"), "utf8"), /^Closes #42/);
    assert.match(readFileSync(join(out, "comment.md"), "utf8"), /通过自动校验/);
  });
});

describe("示例资源地址 → 自动测试", () => {
  test("每行生成一条 classifyResponse 测试，! 开头表示不应被识别", () => {
    const { tests, errors } = parseSamples("https://www.example.com/v/a.xyz\n\n! https://www.example.com/v/a.html\n", "https://www.example.com/watch/1");
    assert.deepEqual(errors, []);
    assert.equal(tests.length, 2);
    assert.equal(tests[0].call, "classifyResponse");
    assert.deepEqual(tests[0].expect, { decision: "resource" });
    assert.equal(tests[0].args[0].pageUrl, "https://www.example.com/watch/1");
    assert.deepEqual(tests[1].expect, { decision: "none" });
    assert.notEqual(tests[0].name, tests[1].name);
  });

  test("非法地址被指出", () => {
    assert.match(parseSamples("ftp://x/y\nnot a url", "").errors.join("\n"), /http\(s\)/);
  });

  test("样本写入规则文件并参与校验；规则识别不了样本时提交失败", () => {
    const dir = scratchRepo();
    const ok = processSubmission({
      root: dir,
      issue: issue(issueBody({ rule: JSON.stringify(localRule), samples: "https://www.example.com/v/a.xyz\n!https://www.example.com/v/a.html" })),
    });
    assert.equal(ok.ok, true, ok.errors.join("\n"));
    assert.equal(ok.sampleTestCount, 2);
    const written = JSON.parse(readFileSync(join(dir, ok.file), "utf8"));
    assert.equal(written.tests.length, 2);

    const bad = scratchRepo();
    const failed = processSubmission({
      root: bad,
      issue: issue(issueBody({ rule: JSON.stringify(localRule), samples: "https://www.example.com/v/a.mp9" })),
    });
    assert.equal(failed.ok, false);
    assert.ok(failed.errors.some((e) => e.includes("sample resource")));
  });

  test("pr.md 带上样本、说明与测试数量", () => {
    const dir = scratchRepo();
    const event = join(dir, "event.json");
    const body = issueBody({ rule: JSON.stringify(localRule), samples: "https://www.example.com/v/a.xyz", notes: "只在 example.com 生效 ```x" });
    writeFileSync(event, JSON.stringify({ issue: issue(body) }));
    const out = join(dir, "out");
    execFileSync("node", [join(dir, "scripts/submit.mjs"), "--event", event, "--out", out, "--root", dir]);
    const pr = readFileSync(join(out, "pr.md"), "utf8");
    assert.match(pr, /自动生成 1 条/);
    assert.match(pr, /https:\/\/www\.example\.com\/v\/a\.xyz/);
    assert.match(pr, /只在 example\.com 生效 ʼʼʼx/);
  });
});

describe("社区规则归属", () => {
  const submit = (dir, { user, labels = [], rule = localRule }) =>
    processSubmission({
      root: dir,
      issue: { ...issue(issueBody({ rule: JSON.stringify(rule) })), user, labels },
    });
  const alice = { login: "alice", id: 7 };
  const bob = { login: "bob", id: 8 };

  test("同一提交者可更新自己的规则，他人不能覆盖", () => {
    const dir = scratchRepo();
    assert.equal(submit(dir, { user: alice }).ok, true);
    assert.equal(JSON.parse(readFileSync(join(dir, "owners.json"), "utf8"))["community.misc.example-video"].login, "alice");
    assert.equal(submit(dir, { user: alice, rule: { ...localRule, title: "新标题" } }).ok, true);

    const before = readFileSync(join(dir, "rules/community/example.com.json"), "utf8");
    const denied = submit(dir, { user: bob, rule: { ...localRule, title: "恶意" } });
    assert.equal(denied.ok, false);
    assert.match(denied.errors[0], /@alice.*不能覆盖/);
    assert.equal(readFileSync(join(dir, "rules/community/example.com.json"), "utf8"), before);
  });

  test("维护者标签允许覆盖并转移归属", () => {
    const dir = scratchRepo();
    submit(dir, { user: alice });
    const result = submit(dir, { user: bob, labels: [{ name: MAINTAINER_LABEL }], rule: { ...localRule, title: "接管" } });
    assert.equal(result.ok, true, result.errors.join("\n"));
    assert.equal(result.overrodeOwner, "alice");
    assert.equal(JSON.parse(readFileSync(join(dir, "owners.json"), "utf8"))["community.misc.example-video"].login, "bob");
  });

  test("没有归属记录的已收录规则同样受保护", () => {
    const dir = scratchRepo();
    writeFileSync(
      join(dir, "rules/community/example.com.json"),
      JSON.stringify({ rules: [{ ...localRule, id: "community.misc.example-video", tier: "community" }] }),
    );
    assert.equal(submit(dir, { user: bob }).ok, false);
  });

  test("文件名：有损清洗追加哈希，普通域名保持可读", () => {
    assert.equal(fileSlug({ match: { host: ["*.Example.com"] } }), "example.com");
    const a = fileSlug({ match: { host: ["example.com:8080"] } });
    const b = fileSlug({ match: { host: ["example.com/8080"] } });
    assert.match(a, /^example\.com-8080-[0-9a-f]{6}$/);
    assert.notEqual(a, b);
    assert.equal(fileSlug({ match: { host: ["..."] } }), null);
  });
});
