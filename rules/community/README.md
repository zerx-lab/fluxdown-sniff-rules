# 社区规则

每个站点一个文件：`<站点域名>.json`，结构 `{ "rules": [...], "tests": [...] }`。
规则 id 以 `community.` 开头，`tier` 为 `community`，`match` 必须限定 `host` 或 `pageHost`。

最方便的提交方式：在 FluxDown 扩展「设置 → 嗅探规则 → 本地规则」里写好并验证规则，点该行的「提交到社区」。
完整说明见仓库根目录 README 与 <https://fluxdown.zerx.dev/docs/zh/browser-extension/sniff-rules/>。
