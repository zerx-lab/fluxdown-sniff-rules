// 访问 GitHub：读取登记仓库的 Latest Release 并下载规则附件；同步 stage-fail issue。
// 只把下载到的内容当数据（JSON）处理，不执行任何来自登记仓库的代码。
import { createHash } from "node:crypto";
import { MAX_PACK_PAYLOAD_BYTES, SOURCE_ASSET } from "./lib.mjs";

const API = "https://api.github.com";

function headers(token) {
  const out = { accept: "application/vnd.github+json", "x-github-api-version": "2022-11-28", "user-agent": "fluxdown-sniff-rules" };
  if (token) out.authorization = `Bearer ${token}`;
  return out;
}

export async function api(path, { token, method = "GET", body } = {}) {
  const response = await fetch(`${API}${path}`, {
    method,
    headers: { ...headers(token), ...(body ? { "content-type": "application/json" } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (response.status === 404) return null;
  if (!response.ok) throw new Error(`GitHub API ${method} ${path} 返回 ${response.status}`);
  return response.status === 204 ? null : response.json();
}

/**
 * 取登记仓库最新正式 Release 的规则附件。
 * 返回 { ok: true, tag, publishedAt, url, sha256, text } 或 { ok: false, error }。
 */
export async function fetchLatestRelease(repo, { token } = {}) {
  let release;
  try {
    release = await api(`/repos/${repo}/releases/latest`, { token });
  } catch (e) {
    return { ok: false, error: `读取 Release 失败：${e.message}` };
  }
  if (release === null) {
    return { ok: false, error: `仓库 ${repo} 不存在、不是公开仓库，或还没有正式 Release（草稿和预发布不算）` };
  }
  const asset = (release.assets ?? []).find((a) => a.name === SOURCE_ASSET);
  if (!asset) return { ok: false, error: `Release ${release.tag_name} 没有名为 ${SOURCE_ASSET} 的附件` };
  const prefix = `https://github.com/${repo}/releases/download/`.toLowerCase();
  if (!String(asset.browser_download_url).toLowerCase().startsWith(prefix)) {
    return { ok: false, error: `附件地址不属于 ${repo} 的 Release` };
  }
  if (asset.size > MAX_PACK_PAYLOAD_BYTES) {
    return { ok: false, error: `附件 ${asset.size} 字节，超过上限 ${MAX_PACK_PAYLOAD_BYTES}` };
  }
  let bytes;
  try {
    const response = await fetch(asset.browser_download_url, { headers: { "user-agent": "fluxdown-sniff-rules" } });
    if (!response.ok) return { ok: false, error: `下载附件返回 ${response.status}` };
    bytes = Buffer.from(await response.arrayBuffer());
  } catch (e) {
    return { ok: false, error: `下载附件失败：${e.message}` };
  }
  if (bytes.length > MAX_PACK_PAYLOAD_BYTES) return { ok: false, error: "附件超过大小上限" };
  const sha256 = createHash("sha256").update(bytes).digest("hex");
  if (typeof asset.digest === "string" && asset.digest !== `sha256:${sha256}`) {
    return { ok: false, error: `附件内容与 GitHub 记录的摘要 ${asset.digest} 不一致` };
  }
  return {
    ok: true,
    tag: release.tag_name,
    publishedAt: release.published_at,
    url: asset.browser_download_url,
    sha256,
    text: bytes.toString("utf8"),
  };
}

/** stage-fail issue 标题；按命名空间一一对应。 */
export function failIssueTitle(ns) {
  return `stage-fail: ${ns}`;
}

/**
 * 同步收录失败 issue：失败的命名空间开 / 更新 issue 并 @ 仓库 owner，恢复的关闭。
 * `results` = { failures: { ns: { repo, errors } }, healthy: [ns] }。
 */
export async function syncFailIssues(repoFullName, results, { token }) {
  const open = (await api(`/repos/${repoFullName}/issues?state=open&labels=stage-fail&per_page=100`, { token })) ?? [];
  const byTitle = new Map(open.map((issue) => [issue.title, issue]));
  for (const [ns, failure] of Object.entries(results.failures)) {
    const owner = failure.repo.split("/")[0];
    const body = [
      `@${owner} 收录 \`${failure.repo}\` 的最新 Release 失败，已收录的旧版本继续生效。修复后发布新的 Release，下次收录（每小时）成功会自动关闭本 issue。`,
      "",
      ...failure.errors.map((error) => `- ${error}`),
      "",
      "说明见 https://fluxdown.zerx.dev/docs/zh/contributing/sniff-rules/",
    ].join("\n");
    const existing = byTitle.get(failIssueTitle(ns));
    if (!existing) {
      await api(`/repos/${repoFullName}/issues`, { token, method: "POST", body: { title: failIssueTitle(ns), body, labels: ["stage-fail"] } });
    } else if (existing.body !== body) {
      await api(`/repos/${repoFullName}/issues/${existing.number}`, { token, method: "PATCH", body: { body } });
    }
  }
  for (const ns of results.healthy) {
    const existing = byTitle.get(failIssueTitle(ns));
    if (existing) {
      await api(`/repos/${repoFullName}/issues/${existing.number}/comments`, { token, method: "POST", body: { body: "已成功收录，自动关闭。" } });
      await api(`/repos/${repoFullName}/issues/${existing.number}`, { token, method: "PATCH", body: { state: "closed" } });
    }
  }
}
