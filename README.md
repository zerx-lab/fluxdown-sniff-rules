# FluxDown 嗅探规则

[FluxDown](https://github.com/zerx-lab/FluxDown) 浏览器扩展的**官方规则**与**社区规则索引**。规则决定哪些网络请求被识别为可下载资源、怎样区分音视频轨、从哪些接口响应里提取直链等。

本仓库每小时运行一次：收录登记仓库的新 Release → 用扩展同款校验器检查全部规则并运行规则测试 → 统一签名发布到 `dist/`。FluxDown 桌面端验签后下发给扩展，不需要等扩展发版。

*English: official rules plus an index of community rule repositories for the FluxDown browser extension. Authors keep rules in their own repository, register it here once, and every later Release is picked up automatically. Guide: <https://fluxdown.zerx.dev/docs/en/contributing/sniff-rules/>.*

文档：[嗅探规则参考](https://fluxdown.zerx.dev/docs/zh/browser-extension/sniff-rules/)（每个字段的含义） · [贡献嗅探规则](https://fluxdown.zerx.dev/docs/zh/contributing/sniff-rules/)（完整流程）

## 两种贡献方式

| | 维护自己的规则仓库（推荐长期维护者） | 一次性提交（Issue 表单） |
| --- | --- | --- |
| 规则放在哪 | 你自己的公开仓库 | 本仓库 `rules/community/` |
| 规则 id | `community.<你的命名空间>.<名字>` | `community.misc.<名字>` |
| 首次 | 提一个只改 `registry.json` 的登记 PR，维护者审核 | 提 Issue，机器人开 PR，维护者审核 |
| 之后更新 | **发 Release 即可，一小时内自动收录，不再审核** | 每次都要再提 Issue 并审核 |
| 能覆盖的站点 | 只能是你登记时认领的站点（独占） | 任何**未被认领**的站点 |

## 维护自己的规则仓库

### 1. 用模板创建仓库

打开 [zerx-lab/fluxdown-sniff-rules-template](https://github.com/zerx-lab/fluxdown-sniff-rules-template)，**Use this template → Create a new repository**（必须 Public）。模板自带示例规则、检查工作流和发布工作流。

### 2. 编辑 `sniff-rules.json`

```json
{
  "namespace": "alice",
  "hosts": ["example.com", "example-cdn.net"],
  "rules": [
    {
      "id": "community.alice.example-video",
      "version": 1,
      "tier": "community",
      "title": "Example：把 .xyz 文件识别为视频",
      "stage": "response",
      "match": { "host": ["example.com"], "ext": ["xyz"] },
      "action": { "kind": "resource", "type": "video" }
    }
  ],
  "tests": [
    {
      "name": "识别 xyz 视频",
      "call": "classifyResponse",
      "args": [{ "url": "https://cdn.example.com/a.xyz", "pageUrl": "https://example.com/", "size": 0, "attachment": false }],
      "expect": { "decision": "resource", "type": "video" }
    }
  ]
}
```

| 字段 | 要求 |
| --- | --- |
| `namespace` | 2–31 个小写字母 / 数字 / 连字符；不能是 `misc`、`official`、`builtin`、`fluxdown`、`community`、`local`、`plugin`、`test`；全仓唯一，登记后不能改 |
| `hosts` | 拟认领站点，只用于登记前自检；登记后以 `registry.json` 为准 |
| `rules[].id` | `community.<namespace>.<名字>`，全仓唯一 |
| `rules[].tier` | `community` |
| 站点 | 规则里出现的每个 `host` / `pageHost`（含 `exclude`）和 `mirror.hosts` 都必须落在认领站点内；`extract` / `dom` 产出的下载地址在扩展里也只接受规则自身 `host` / `pageHost` 范围内的地址 |
| `tests` | 可选但强烈建议；与本仓库所有规则一起运行，失败不收录 |

规则字段的完整说明见[嗅探规则参考](https://fluxdown.zerx.dev/docs/zh/browser-extension/sniff-rules/)。

### 3. 自检

模板仓库的 `check` 工作流在每次推送时自动运行（调用本仓库的 `author-check` 可复用工作流）。本地运行：

```bash
git clone https://github.com/zerx-lab/fluxdown-sniff-rules
node fluxdown-sniff-rules/scripts/check-source.mjs --file sniff-rules.json --repo <owner>/<repo>
```

### 4. 发布 Release

推送 `v*` 标签（`git tag v1.0.0 && git push origin v1.0.0`），模板的 `release` 工作流检查通过后创建 Release 并上传 `sniff-rules.json`。手动发布也可以：附件名必须是 `sniff-rules.json`，不能是草稿或预发布。

### 5. 登记（只需一次）

提一个**只修改 `registry.json`** 的 PR，在 `sources` 末尾追加：

```json
{ "ns": "alice", "repo": "alice/fluxdown-rules", "hosts": ["example.com", "example-cdn.net"], "description": "Example 站点的视频识别" }
```

| 字段 | 要求 |
| --- | --- |
| `ns` | 与 `sniff-rules.json` 的 `namespace` 相同 |
| `repo` | `owner/name`；一个仓库只能登记一个命名空间 |
| `hosts` | 认领的站点：普通域名，自动包含全部子域；不能带 `=`、`*`、协议、路径；至少两段（`com` 不行）；不能与他人的认领重叠 |
| `description` | 可选，不超过 200 字 |

`registry-check` 机器人会拉取你的 Latest Release、跑与收录完全相同的检查，并在 PR 里评论结果与规则清单。维护者审核认领范围是否合理后合并，一小时内收录。

### 6. 更新

- 改规则 → **改动过的规则 `version` 加一** → 发新的 Release。不再需要 PR 或审核。
- 收录失败时，本仓库会开 `stage-fail: <ns>` issue 并 @ 仓库 owner，**已收录的旧版本继续生效**；修好后发新 Release，issue 自动关闭。
- 下列情况会被拒收：替换已收录 Release 的附件（请永远发新 Release）；最新 Release 比已收录的旧；改了规则内容但 `version` 没变大；站点超出认领；规则测试失败。
- 扩大认领、更换仓库、停止维护：提 PR 修改或删除你在 `registry.json` 的条目。更换仓库需原维护者在 PR 中确认；删除条目后你的规则会从社区包移除。

## 一次性提交（不建仓库）

在扩展「设置 → 嗅探规则 → 本地规则」里写好并验证规则，点该行的「提交到社区」，浏览器打开预填好的 [Issue 表单](../../issues/new?template=community-rule.yml)。机器人自动校验：通过则开 PR；不通过回复原因，**编辑 Issue** 即可重新校验。规则会以 `community.misc.<名字>` 存进 `rules/community/<站点>.json`。已被登记仓库认领的站点不接受此处提交。

## 目录

| 路径 | 内容 |
| --- | --- |
| `rules/official/*.json` | 官方规则（维护者维护，可用 `preempt`、全局 `strip-params` 等特权） |
| `rules/community/*.json` | 本仓库托管的一次性社区规则（命名空间 `misc`） |
| `registry.json` | 登记的社区规则仓库：命名空间 ↔ 仓库 ↔ 认领站点 |
| `sources/<ns>/` | 收录任务生成：已收录的 `sniff-rules.json` 快照与 `pin.json`（Release 标签、sha256），**勿手改** |
| `revocations.json` | 吊销列表源：撤回有问题的规则（任何层级） |
| `dist/` | 签名后的规则包与吊销列表，**勿手改** |
| `vendor/fluxdown-sniff-rules.mjs` | 从扩展源码打包的校验器与求值器，**勿手改** |
| `keys.json` | 发布公钥（与桌面端内置公钥一致），签名后回验用 |
| `scripts/` | 收录、校验、签名、登记检查、Issue 转 PR 脚本及测试 |

## 工作流

| 工作流 | 触发 | 作用 |
| --- | --- | --- |
| `publish` | 每小时；main 上规则源变化；手动 | 收录登记仓库 → 校验 → 有变化或有效期将尽时签名发布；同步 `stage-fail` issue |
| `registry-check` | 修改 `registry.json` 的 PR | 拉取新增 / 改动条目的 Release，检查并评论 |
| `check` | PR | 脚本测试 + 全仓校验与规则测试 |
| `submit` | `community-rule` Issue | 一次性提交转 PR |
| `author-check` | 被登记仓库调用 | 作者仓库的自检 |

## 发布与签名

- 社区包与吊销列表有效期 30 天，剩余不足 14 天时续签；每次内容变化或续签 `sequence` 加一，桌面端只接受更大的 `sequence`。
- 签名私钥只在仓库 Secret `SNIFF_SIGNING_KEY`（keyId `SNIFF_SIGNING_KEY_ID`），仅 `publish` 读取；签名后用 `keys.json` 回验。作者不持有任何密钥。
- 吊销专用密钥离线冷存，供紧急情况在 CI 之外签发吊销列表。

## 本地运行

Node.js 22+，无第三方依赖：

```bash
node --test scripts/*.test.mjs     # 脚本测试
node scripts/build.mjs --check     # 全仓校验 + 规则测试 + 预览将签发的文档
GITHUB_TOKEN=… node scripts/stage.mjs --root <副本目录>   # 在副本上演练收录
```

## 维护者：同步扩展

扩展的校验 / 求值代码或内置规则变化后，在 FluxDown 仓库根目录运行：

```bash
bun scripts/sniff-rules/sync-repo.ts vendor --repo ../fluxdown-sniff-rules   # 更新 vendor/
bun scripts/sniff-rules/sync-repo.ts seed --repo ../fluxdown-sniff-rules     # 官方包发布后更新扩展随包快照
```
