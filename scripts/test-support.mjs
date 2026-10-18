// 测试用临时仓库：带上本仓的官方规则、vendor、脚本与公钥，但社区规则与吊销列表从空开始，
// 测试结果不随仓库里已合并的社区规则变化。
import { cpSync, mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

export const ROOT = new URL("..", import.meta.url).pathname;

export function scratchRepo() {
  const dir = mkdtempSync(join(tmpdir(), "sniff-rules-"));
  for (const entry of ["rules/official", "vendor", "scripts", "keys.json"]) {
    cpSync(join(ROOT, entry), join(dir, entry), { recursive: true });
  }
  mkdirSync(join(dir, "rules", "community"), { recursive: true });
  writeFileSync(join(dir, "revocations.json"), '{ "entries": [] }\n');
  return dir;
}
