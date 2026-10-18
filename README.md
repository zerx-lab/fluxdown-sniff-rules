# FluxDown 嗅探规则

[FluxDown](https://github.com/zerx-lab/FluxDown) 浏览器扩展的**官方**与**社区**嗅探规则源。规则决定哪些网络请求被识别为可下载资源、如何区分音视频轨、从哪些接口响应里提取直链等。

合并到 `main` 后，CI 自动校验、签名并发布到 `dist/`；FluxDown 桌面端验签后下发给扩展，无需等扩展发版。

*English: this repo holds the official and community sniff rules for the FluxDown browser extension. Contribute with the "Submit to community" button next to a local rule in the extension, or open a [community rule issue](../../issues/new?template=community-rule.yml). Field reference: <https://fluxdown.zerx.dev/docs/en/browser-extension/sniff-rules/>.*

## 怎么贡献规则

**推荐：从扩展一键提交**

1. 扩展「设置 → 嗅探规则 → 本地规则」里新建规则，用「规则测试」确认在目标网站上生效。
2. 在该规则行点「提交到社区」，浏览器会打开预填好的 Issue，补上示例页面后提交。
3. 机器人自动校验：通过则开 Pull Request 并回复链接；不通过会回复原因，**编辑 Issue** 即可重新校验。
4. 维护者审核合并后自动签名发布。桌面端每 6 小时检查一次规则仓、扩展每 6 小时向桌面端同步一次，所以通常 12 小时内所有用户生效；在扩展「嗅探规则」页点「立即同步」可提前拉取桌面端已有的版本。

**也可以直接提 Pull Request**：在 `rules/community/<站点域名>.json` 新增或修改规则文件，CI（`check`）会跑同样的校验和测试。

字段含义、各阶段可用动作和示例见文档：[嗅探规则](https://fluxdown.zerx.dev/docs/zh/browser-extension/sniff-rules/) · [贡献嗅探规则](https://fluxdown.zerx.dev/docs/zh/contributing/sniff-rules/)。

## 目录

| 路径 | 内容 |
| --- | --- |
| `rules/official/*.json` | 官方规则（维护者维护，可用 `preempt`、全局 `strip-params` 等特权） |
| `rules/community/*.json` | 社区规则（每站点一个文件，必须限定 `host` / `pageHost`） |
| `revocations.json` | 吊销列表源：撤回有问题的规则（任何层级，含扩展内置规则） |
| `dist/` | CI 签发的规则包与吊销列表（签名信封），**勿手改** |
| `vendor/fluxdown-sniff-rules.mjs` | 从扩展源码打包的校验器与求值器，**勿手改** |
| `keys.json` | 发布公钥（与桌面端内置公钥一致），签名后回验用 |
| `scripts/` | 校验、签名、Issue 转 PR 脚本与测试 |

## 规则文件

```json
{
  "rules": [
    {
      "id": "community.example.video",
      "version": 1,
      "tier": "community",
      "title": "Example：识别 .xyz 视频",
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

- `tier` 必须与所在目录一致，`id` 以 `<tier>.` 开头且全仓唯一。
- 改动已发布的规则时 `version` 加一（吊销按版本生效）。
- `tests` 可选但强烈建议：用 builtin + 本仓全部规则编译引擎后调用 `call`，结果按「对象只比较写出的键」与 `expect` 比较。

## 本地运行

需要 Node.js 22+，无第三方依赖。

```bash
node --test scripts/*.test.mjs     # 脚本自身测试
node scripts/build.mjs --check     # 校验全部规则 + 跑规则测试 + 预览将签发的文档
```

## 发布与签名

- `publish` 工作流：`main` 上规则源变化时签发；每日定时任务在社区包 / 吊销列表有效期（30 天）剩余不足 14 天时续签。
- 内容变化或续签都会让 `sequence` 加一；桌面端只接受更大的 `sequence`。
- 签名私钥只存在仓库 Secret `SNIFF_SIGNING_KEY`（keyId 在 `SNIFF_SIGNING_KEY_ID`），只有 `publish` 工作流读取；签名后会用 `keys.json` 的公钥回验。
- 吊销列表另有离线冷存的吊销专用密钥，供紧急情况在 CI 之外签发。

## 维护者：同步扩展

扩展的校验 / 求值代码或内置规则变化后，在 FluxDown 仓库根目录运行：

```bash
bun scripts/sniff-rules/sync-repo.ts vendor --repo ../fluxdown-sniff-rules   # 更新 vendor/
bun scripts/sniff-rules/sync-repo.ts seed --repo ../fluxdown-sniff-rules     # 官方包发布后，更新扩展随包快照
```
