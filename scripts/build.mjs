#!/usr/bin/env node
// 校验规则源并发布签名规则包。
//
//   node scripts/build.mjs --check
//       校验 + 跑规则测试 + 列出将要重新签发的文档；不签名、不写盘。
//   node scripts/build.mjs --sign [--message <file>]
//       额外签名并写入 dist/{official,community,revocations}.json。
//       私钥取环境变量 SNIFF_SIGNING_KEY（PKCS#8 PEM），keyId 取 SNIFF_SIGNING_KEY_ID。
//       --message 把发布摘要写到文件，供 CI 作提交信息。
//   --root <dir>  仓库根（默认当前目录）；--now <ISO>  固定当前时间（测试用）。
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import {
  checkRepository,
  makePack,
  makeRevocations,
  nextMeta,
  payloadLimit,
  readPublished,
  signEnvelope,
} from "./lib.mjs";

function arg(name) {
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

const root = resolve(arg("--root") ?? ".");
const signing = process.argv.includes("--sign");
if (!signing && !process.argv.includes("--check")) {
  console.error("用法: build.mjs --check | --sign [--message <file>] [--root <dir>] [--now <ISO>]");
  process.exit(2);
}
const now = arg("--now") ? Date.parse(arg("--now")) : Date.now();

const { sources, errors } = checkRepository(root);
if (errors.length > 0) {
  console.error(`校验失败（${errors.length} 项）：`);
  for (const error of errors) console.error(`  - ${error}`);
  process.exit(1);
}
console.log(
  `校验通过：官方 ${sources.rules.official.length} 条、社区 ${sources.rules.community.length} 条、` +
    `吊销 ${sources.revocationEntries.length} 条、测试 ${sources.tests.length} 条`,
);

const dist = join(root, "dist");
const docs = [
  {
    kind: "official",
    body: sources.rules.official,
    bodyOf: (doc) => doc.rules,
    expires: false,
    build: (meta) => makePack("official", sources.rules.official, meta),
  },
  {
    kind: "community",
    body: sources.rules.community,
    bodyOf: (doc) => doc.rules,
    expires: true,
    build: (meta) => makePack("community", sources.rules.community, meta),
  },
  {
    kind: "revocations",
    body: sources.revocationEntries,
    bodyOf: (doc) => doc.entries,
    expires: true,
    build: (meta) => makeRevocations(sources.revocationEntries, meta),
  },
];

const planned = [];
for (const doc of docs) {
  const previous = readPublished(join(dist, `${doc.kind}.json`));
  const meta = nextMeta({ previous, body: doc.body, bodyOf: doc.bodyOf, expires: doc.expires, now });
  if (meta === null) {
    console.log(`${doc.kind}: 无变化（sequence ${previous.sequence}）`);
    continue;
  }
  const payload = Buffer.from(JSON.stringify(doc.build(meta)));
  if (payload.length > payloadLimit(doc.kind)) {
    console.error(`${doc.kind}: 载荷 ${payload.length} 字节超过上限 ${payloadLimit(doc.kind)}`);
    process.exit(1);
  }
  console.log(`${doc.kind}: 将签发 sequence ${meta.sequence}${meta.expiresAt ? `，有效期至 ${meta.expiresAt}` : ""}`);
  planned.push({ kind: doc.kind, meta, payload });
}

if (!signing) process.exit(0);
if (planned.length === 0) {
  console.log("没有需要签发的文档");
  process.exit(0);
}

const pem = process.env.SNIFF_SIGNING_KEY;
const keyId = process.env.SNIFF_SIGNING_KEY_ID;
if (!pem || !keyId) {
  console.error("缺少 SNIFF_SIGNING_KEY / SNIFF_SIGNING_KEY_ID");
  process.exit(1);
}
const trusted = JSON.parse(readFileSync(join(root, "keys.json"), "utf8")).release;
mkdirSync(dist, { recursive: true });
for (const doc of planned) {
  writeFileSync(join(dist, `${doc.kind}.json`), signEnvelope(doc.payload, { pem, keyId, trusted }));
}
const summary = planned.map((doc) => `${doc.kind} #${doc.meta.sequence}`).join(", ");
console.log(`已签发：${summary}`);
const messageFile = arg("--message");
if (messageFile) writeFileSync(messageFile, `publish: ${summary}\n`);
