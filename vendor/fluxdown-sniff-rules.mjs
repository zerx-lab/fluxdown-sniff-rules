// 由 FluxDown 仓库 scripts/sniff-rules/sync-repo.ts vendor 生成，勿手改。
// 源：fluxDown/rules/{schema,validate,engine,glob,url}.ts 与 builtin.json。
// fluxDown/rules/builtin.json
var builtin_default = {
  format: "fluxdown-sniff-pack",
  packId: "builtin",
  sequence: 1,
  engine: 1,
  issuedAt: "2026-10-15T00:00:00Z",
  rules: [
    {
      id: "builtin.ext.video",
      version: 1,
      tier: "builtin",
      stage: "response",
      priority: 20,
      match: {
        ext: [
          "mp4",
          "mkv",
          "avi",
          "mov",
          "wmv",
          "flv",
          "webm",
          "ts",
          "m4v",
          "3gp",
          "mpg",
          "mpeg",
          "f4v",
          "vob",
          "ogv"
        ]
      },
      action: {
        kind: "resource",
        type: "video"
      }
    },
    {
      id: "builtin.ext.audio",
      version: 1,
      tier: "builtin",
      stage: "response",
      priority: 20,
      match: {
        ext: [
          "mp3",
          "flac",
          "wav",
          "aac",
          "ogg",
          "wma",
          "m4a",
          "opus",
          "ape",
          "alac",
          "aiff"
        ]
      },
      action: {
        kind: "resource",
        type: "audio"
      }
    },
    {
      id: "builtin.ext.document",
      version: 1,
      tier: "builtin",
      stage: "response",
      priority: 20,
      match: {
        ext: [
          "pdf",
          "doc",
          "docx",
          "xls",
          "xlsx",
          "ppt",
          "pptx",
          "txt",
          "rtf",
          "epub",
          "mobi",
          "csv",
          "odt",
          "ods",
          "odp"
        ]
      },
      action: {
        kind: "resource",
        type: "document"
      }
    },
    {
      id: "builtin.ext.archive",
      version: 1,
      tier: "builtin",
      stage: "response",
      priority: 20,
      match: {
        ext: [
          "zip",
          "rar",
          "7z",
          "tar",
          "gz",
          "bz2",
          "xz",
          "iso",
          "img",
          "zst",
          "lz",
          "cab",
          "z"
        ]
      },
      action: {
        kind: "resource",
        type: "archive"
      }
    },
    {
      id: "builtin.ext.image",
      version: 1,
      tier: "builtin",
      stage: "response",
      priority: 20,
      requires: "sniffImages",
      match: {
        ext: [
          "jpg",
          "jpeg",
          "png",
          "gif",
          "webp",
          "svg",
          "bmp",
          "ico",
          "tiff",
          "psd",
          "raw",
          "heic",
          "avif"
        ]
      },
      action: {
        kind: "resource",
        type: "image"
      }
    },
    {
      id: "builtin.ext.executable",
      version: 1,
      tier: "builtin",
      stage: "response",
      priority: 20,
      match: {
        ext: [
          "exe",
          "msi",
          "dmg",
          "deb",
          "rpm",
          "appimage",
          "apk",
          "ipa",
          "snap",
          "flatpak"
        ]
      },
      action: {
        kind: "resource",
        type: "executable"
      }
    },
    {
      id: "builtin.ext.torrent",
      version: 1,
      tier: "builtin",
      stage: "response",
      priority: 20,
      match: {
        ext: [
          "torrent"
        ]
      },
      action: {
        kind: "resource",
        type: "torrent"
      }
    },
    {
      id: "builtin.ext.stream",
      version: 1,
      tier: "builtin",
      stage: "response",
      priority: 20,
      match: {
        ext: [
          "m3u8",
          "m3u",
          "mpd",
          "m4s"
        ]
      },
      action: {
        kind: "resource",
        type: "stream"
      }
    },
    {
      id: "builtin.ext.subtitle",
      version: 1,
      tier: "builtin",
      stage: "response",
      priority: 20,
      match: {
        ext: [
          "vtt",
          "srt",
          "ass",
          "ssa",
          "sub",
          "idx",
          "sup",
          "lrc"
        ]
      },
      action: {
        kind: "resource",
        type: "subtitle"
      }
    },
    {
      id: "builtin.mime.video",
      version: 1,
      tier: "builtin",
      stage: "response",
      priority: 10,
      match: {
        mime: [
          "video/*"
        ]
      },
      action: {
        kind: "resource",
        type: "video"
      }
    },
    {
      id: "builtin.mime.audio",
      version: 1,
      tier: "builtin",
      stage: "response",
      priority: 10,
      match: {
        mime: [
          "audio/*"
        ]
      },
      action: {
        kind: "resource",
        type: "audio"
      }
    },
    {
      id: "builtin.mime.stream",
      version: 2,
      tier: "builtin",
      stage: "response",
      priority: 11,
      match: {
        mime: [
          "application/vnd.apple.mpegurl",
          "application/x-mpegurl",
          "application/mpegurl",
          "application/octet-stream-m3u8",
          "audio/mpegurl",
          "audio/x-mpegurl",
          "application/dash+xml",
          "application/m4s"
        ]
      },
      action: {
        kind: "resource",
        type: "stream"
      }
    },
    {
      id: "builtin.mime.image",
      version: 1,
      tier: "builtin",
      stage: "response",
      priority: 10,
      requires: "sniffImages",
      match: {
        mime: [
          "image/*"
        ]
      },
      action: {
        kind: "resource",
        type: "image"
      }
    },
    {
      id: "builtin.mime.classify.document",
      version: 1,
      tier: "builtin",
      stage: "response",
      priority: 10,
      classifyOnly: true,
      match: {
        mime: [
          "application/pdf",
          "application/msword",
          "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
          "application/vnd.ms-excel",
          "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
          "application/vnd.ms-powerpoint",
          "application/vnd.openxmlformats-officedocument.presentationml.presentation",
          "application/epub+zip",
          "text/csv",
          "application/vnd.openxmlformats-officedocument.*",
          "application/vnd.ms-*"
        ]
      },
      action: {
        kind: "resource",
        type: "document"
      }
    },
    {
      id: "builtin.mime.classify.archive",
      version: 1,
      tier: "builtin",
      stage: "response",
      priority: 10,
      classifyOnly: true,
      match: {
        mime: [
          "application/zip",
          "application/x-rar-compressed",
          "application/x-7z-compressed",
          "application/gzip",
          "application/x-tar",
          "application/x-bzip2",
          "application/x-xz",
          "application/x-iso9660-image",
          "application/zstd"
        ]
      },
      action: {
        kind: "resource",
        type: "archive"
      }
    },
    {
      id: "builtin.mime.classify.executable",
      version: 1,
      tier: "builtin",
      stage: "response",
      priority: 10,
      classifyOnly: true,
      match: {
        mime: [
          "application/x-msdownload",
          "application/x-msi",
          "application/vnd.android.package-archive",
          "application/x-apple-diskimage",
          "application/vnd.debian.binary-package"
        ]
      },
      action: {
        kind: "resource",
        type: "executable"
      }
    },
    {
      id: "builtin.mime.classify.torrent",
      version: 1,
      tier: "builtin",
      stage: "response",
      priority: 10,
      classifyOnly: true,
      match: {
        mime: [
          "application/x-bittorrent"
        ]
      },
      action: {
        kind: "resource",
        type: "torrent"
      }
    },
    {
      id: "builtin.mime.classify.subtitle",
      version: 1,
      tier: "builtin",
      stage: "response",
      priority: 10,
      classifyOnly: true,
      match: {
        mime: [
          "text/vtt",
          "application/x-subrip",
          "text/x-ssa",
          "text/x-ass",
          "application/x-subtitle"
        ]
      },
      action: {
        kind: "resource",
        type: "subtitle"
      }
    },
    {
      id: "builtin.noise.substr",
      version: 1,
      tier: "builtin",
      stage: "response",
      priority: 30,
      exclude: [
        {
          attachment: true
        }
      ],
      match: {
        url: [
          "*google-analytics.com*",
          "*googletagmanager.com*",
          "*analytics.google.com*",
          "*doubleclick.net*",
          "*googlesyndication.com*",
          "*googleadservices.com*",
          "*google.com/pagead*",
          "*facebook.com/tr*",
          "*connect.facebook.net*",
          "*fbcdn.net/signals*",
          "*hotjar.com*",
          "*clarity.ms*",
          "*mixpanel.com*",
          "*segment.io*",
          "*segment.com*",
          "*amplitude.com*",
          "*sentry.io*",
          "*bugsnag.com*",
          "*newrelic.com*",
          "*nr-data.net*",
          "*adsense*",
          "*adservice*",
          "*ad.doubleclick*",
          "*moat.com*",
          "*adsrvr.org*",
          "*advertising.com*",
          "*criteo.com*",
          "*outbrain.com*",
          "*taboola.com*",
          "*adnxs.com*",
          "*cdn.mxpnl.com*",
          "*stats.wp.com*",
          "*pixel.wp.com*",
          "*bat.bing.com*",
          "*sb.scorecardresearch.com*",
          "*b.scorecardresearch.com*"
        ]
      },
      action: {
        kind: "ignore"
      }
    },
    {
      id: "builtin.noise.hosts",
      version: 1,
      tier: "builtin",
      stage: "response",
      priority: 30,
      match: {
        host: [
          "=www.google-analytics.com",
          "=ssl.google-analytics.com",
          "=stats.g.doubleclick.net",
          "=cm.g.doubleclick.net",
          "=pixel.facebook.com",
          "=www.facebook.com",
          "=tr.snapchat.com",
          "=analytics.tiktok.com",
          "=analytics.twitter.com"
        ]
      },
      action: {
        kind: "ignore"
      }
    },
    {
      id: "builtin.noise.paths",
      version: 1,
      tier: "builtin",
      stage: "response",
      priority: 30,
      exclude: [
        {
          ext: [
            "mp4",
            "mkv",
            "avi",
            "mov",
            "wmv",
            "flv",
            "webm",
            "ts",
            "m4v",
            "3gp",
            "mpg",
            "mpeg",
            "f4v",
            "vob",
            "ogv",
            "mp3",
            "flac",
            "wav",
            "aac",
            "ogg",
            "wma",
            "m4a",
            "opus",
            "ape",
            "alac",
            "aiff",
            "pdf",
            "doc",
            "docx",
            "xls",
            "xlsx",
            "ppt",
            "pptx",
            "txt",
            "rtf",
            "epub",
            "mobi",
            "csv",
            "odt",
            "ods",
            "odp",
            "zip",
            "rar",
            "7z",
            "tar",
            "gz",
            "bz2",
            "xz",
            "iso",
            "img",
            "zst",
            "lz",
            "cab",
            "z",
            "exe",
            "msi",
            "dmg",
            "deb",
            "rpm",
            "appimage",
            "apk",
            "ipa",
            "snap",
            "flatpak",
            "torrent",
            "m3u8",
            "m3u",
            "mpd",
            "m4s",
            "vtt",
            "srt",
            "ass",
            "ssa",
            "sub",
            "idx",
            "sup",
            "lrc"
          ]
        },
        {
          attachment: true
        }
      ],
      match: {
        pathRegex: "/(?:api/v\\d+(?:/|$)|graphql(?:/|$)|_next/static/|static/(?:js|css|media)/|assets/fonts/|fonts/|favicon[^/]*$|sw\\.js$|workbox-[^/]*$|manifest\\.json$|robots\\.txt$|sitemap[^/]*$|__/|(?:beacon|collect|pixel|track|log|telemetry)(?:\\.[a-z0-9]{1,32})?(?:/|$))"
      },
      action: {
        kind: "ignore"
      }
    },
    {
      id: "builtin.noise.api",
      version: 1,
      tier: "builtin",
      stage: "response",
      priority: 30,
      exclude: [
        {
          attachment: true
        }
      ],
      match: {
        pathRegex: "/graphql(?:/|$)",
        hasExt: false
      },
      action: {
        kind: "ignore"
      }
    },
    {
      id: "builtin.normalize.strip",
      version: 1,
      tier: "builtin",
      stage: "normalize",
      match: {},
      action: {
        kind: "strip-params",
        params: [
          "_",
          "__",
          "t",
          "ts",
          "timestamp",
          "v",
          "ver",
          "version",
          "cache",
          "cb",
          "nocache",
          "rand",
          "random",
          "r",
          "bust",
          "token",
          "auth",
          "signature",
          "sig",
          "sign",
          "expire",
          "expires",
          "e",
          "st",
          "nva",
          "nvb",
          "utm_source",
          "utm_medium",
          "utm_campaign",
          "utm_term",
          "utm_content",
          "fbclid",
          "gclid",
          "msclkid",
          "twclid",
          "ref",
          "referer",
          "referrer",
          "source",
          "start",
          "end",
          "begin",
          "offset",
          "sq",
          "rn",
          "rbuf"
        ]
      }
    },
    {
      id: "builtin.normalize.query-ext",
      version: 1,
      tier: "builtin",
      stage: "normalize",
      match: {},
      action: {
        kind: "filename",
        extFromQuery: [
          "format",
          "ext",
          "fm"
        ]
      }
    }
  ]
};
// fluxDown/utils/domain-exclusion.ts
function normalizeDomain(input) {
  let text = input.trim().toLowerCase();
  if (!text)
    return null;
  text = text.replace(/^\*\./, "");
  let host;
  try {
    host = new URL(text.includes("://") ? text : `http://${text}`).hostname;
  } catch {
    return null;
  }
  host = host.replace(/^\.+/, "").replace(/\.+$/, "");
  return host || null;
}

// fluxDown/rules/glob.ts
function asciiLower(s) {
  return s.replace(/[A-Z]/g, (c) => String.fromCharCode(c.charCodeAt(0) + 32));
}
function urlGlobMatch(pattern, url) {
  return globSegments(asciiLower(pattern), asciiLower(url));
}
function globSegments(pattern, text) {
  if (!pattern.includes("*")) {
    return pattern === text;
  }
  const parts = pattern.split("*");
  const n = parts.length;
  let pos = 0;
  for (let i = 0;i < n; i++) {
    const part = parts[i];
    if (part === "")
      continue;
    if (i === 0) {
      if (!text.slice(pos).startsWith(part))
        return false;
      pos += part.length;
    } else if (i === n - 1) {
      if (!text.slice(pos).endsWith(part))
        return false;
    } else {
      const idx = text.slice(pos).indexOf(part);
      if (idx < 0)
        return false;
      pos += idx + part.length;
    }
  }
  return true;
}
function parseHostPattern(pattern) {
  const raw = pattern.trim();
  const exact = raw.startsWith("=");
  const body = exact ? raw.slice(1) : raw;
  if (body.trim().startsWith("*."))
    return null;
  const domain = normalizeDomain(body);
  return domain ? { domain, exact } : null;
}
function hostMatchesPattern(host, p) {
  const h = host.toLowerCase();
  return p.exact ? h === p.domain : h === p.domain || h.endsWith(`.${p.domain}`);
}

// fluxDown/rules/schema.ts
var RULE_ENGINE_VERSION = 1;
var TIER_RANK = {
  local: 0,
  official: 1,
  plugin: 2,
  community: 3,
  builtin: 4
};
var STAGE_ACTIONS = {
  response: ["resource", "ignore"],
  normalize: ["strip-params", "filename", "mirror"],
  track: ["track"],
  body: ["extract", "manifest"],
  dom: ["dom"],
  page: ["title", "player"],
  request: ["headers"]
};
var FORBIDDEN_RULE_HEADERS = new Set([
  "cookie",
  "authorization",
  "proxy-authorization",
  "host",
  "content-length",
  "range",
  "connection"
]);

// fluxDown/rules/url.ts
function hostOf(url) {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return "";
  }
}
function pathOf(url) {
  try {
    return new URL(url).pathname;
  } catch {
    return "";
  }
}
function pathExtension(url) {
  try {
    const lastSegment = new URL(url).pathname.split("/").pop() || "";
    const dot = lastSegment.lastIndexOf(".");
    if (dot > 0 && dot < lastSegment.length - 1) {
      return lastSegment.substring(dot + 1).toLowerCase();
    }
  } catch {
    const m = url.match(/\.([a-zA-Z0-9]{1,10})(?:[?#]|$)/);
    if (m)
      return m[1].toLowerCase();
  }
  return "";
}
function extractExtension(url, queryKeys = [], known) {
  const fromPath = pathExtension(url);
  if (fromPath || queryKeys.length === 0)
    return fromPath;
  let params;
  try {
    params = new URL(url).searchParams;
  } catch {
    return "";
  }
  const isKnown = (e) => !known || known.has(e);
  for (const key of queryKeys) {
    const v = params.get(key);
    if (!v)
      continue;
    const e = v.toLowerCase().replace(/^\./, "");
    if (known?.has(e))
      return e;
  }
  for (const v of params.values()) {
    const m = v.toLowerCase().match(/\.([a-z0-9]{1,10})$/);
    if (m && known && isKnown(m[1]))
      return m[1];
  }
  return "";
}

// fluxDown/rules/validate.ts
var MAX_RULES_PER_PACK = 2000;
var MAX_REGEX_LEN = 256;
var MAX_SELECTOR_LEN = 512;
var ID_RE = /^(builtin|official|plugin|community|local)\.[a-z0-9][a-z0-9._-]{1,62}$/;
var RESOURCE_TYPES = new Set([
  "video",
  "audio",
  "document",
  "archive",
  "image",
  "executable",
  "torrent",
  "stream",
  "subtitle",
  "magnet",
  "other"
]);
var NESTED_QUANTIFIER_RE = /\((?:[^()\\]|\\.)*[*+](?:[^()\\]|\\.)*\)[*+{]/;

class PackRejectedError extends Error {
  constructor(message) {
    super(message);
    this.name = "PackRejectedError";
  }
}
function isSafeRegex(pattern) {
  if (typeof pattern !== "string" || pattern.length > MAX_REGEX_LEN)
    return false;
  try {
    new RegExp(pattern, "i");
  } catch {
    return false;
  }
  if (/\\[1-9]|\\k</.test(pattern))
    return false;
  if (/\(\?(?:=|!|<=|<!)/.test(pattern))
    return false;
  if (NESTED_QUANTIFIER_RE.test(pattern))
    return false;
  return true;
}
function checkMatch(m) {
  if (m === undefined)
    return null;
  if (typeof m !== "object" || m === null)
    return "match 不是对象";
  for (const list of [m.host, m.pageHost]) {
    if (list === undefined)
      continue;
    if (!Array.isArray(list))
      return "host/pageHost 须为数组";
    for (const h of list) {
      if (typeof h !== "string" || parseHostPattern(h) === null)
        return `非法 host 模式: ${String(h)}`;
    }
  }
  if (m.pathRegex !== undefined && !isSafeRegex(m.pathRegex))
    return "pathRegex 不安全";
  for (const h of m.header ?? []) {
    if (!h || typeof h.name !== "string" || !isSafeRegex(h.regex))
      return "header 正则不安全";
  }
  return null;
}
var TEMPLATE_REF_RE = /\$\{([^}]*)\}/g;
function templateRefs(t) {
  if (typeof t !== "string")
    return [];
  return [...t.matchAll(TEMPLATE_REF_RE)].map((m) => m[1]);
}
function emitRefs(emit) {
  const url = emit.url;
  const urlRefs = typeof url === "string" ? templateRefs(url) : [
    ...templateRefs(url?.resolve?.base),
    ...templateRefs(url?.resolve?.ref)
  ];
  return [...urlRefs, ...templateRefs(emit.filename), ...templateRefs(emit.quality)];
}
function checkEmit(emit, allowed, tier) {
  if (!emit || typeof emit !== "object")
    return "emit 缺失";
  if (emit.mode !== "resource" && emit.mode !== "preempt")
    return "emit.mode 非法";
  if (emit.mode === "preempt" && tier !== "builtin" && tier !== "official")
    return "preempt 仅允许 builtin / official";
  if (emit.type !== undefined && !RESOURCE_TYPES.has(emit.type))
    return "emit.type 非法";
  if (typeof emit.url !== "string" && !(emit.url && typeof emit.url === "object" && emit.url.resolve))
    return "emit.url 缺失";
  for (const ref of emitRefs(emit)) {
    if (!allowed.has(ref))
      return `模板引用了未定义字段: ${ref}`;
  }
  return null;
}
function checkSelector(selector) {
  if (typeof selector !== "string" || selector.length === 0)
    return "selector 缺失";
  if (selector.length > MAX_SELECTOR_LEN)
    return "selector 过长";
  if (typeof document !== "undefined") {
    try {
      document.createDocumentFragment().querySelector(selector);
    } catch {
      return "selector 非法";
    }
  }
  return null;
}
function hasHost(m) {
  return Array.isArray(m.host) && m.host.length > 0 || Array.isArray(m.pageHost) && m.pageHost.length > 0;
}
function checkRule(rule, expectedTier) {
  if (!rule || typeof rule !== "object")
    return "规则不是对象";
  if (typeof rule.id !== "string" || !ID_RE.test(rule.id))
    return "id 非法";
  if (rule.tier === "plugin" && rule.id.length > 64)
    return "id 非法";
  if (rule.tier !== expectedTier)
    return "tier 与 packId 不符";
  if (!rule.id.startsWith(`${rule.tier}.`))
    return "id 前缀与 tier 不符";
  if (!Number.isInteger(rule.version) || rule.version < 1)
    return "version 非法";
  if (!rule.match || typeof rule.match !== "object")
    return "match 缺失";
  if (!rule.action || typeof rule.action !== "object")
    return "action 缺失";
  const allowedKinds = STAGE_ACTIONS[rule.stage];
  if (!allowedKinds)
    return "stage 非法";
  if (!allowedKinds.includes(rule.action.kind))
    return "stage 与 action 不匹配";
  if (rule.requires !== undefined && rule.requires !== "sniffImages")
    return "requires 非法";
  const matchErr = checkMatch(rule.match);
  if (matchErr)
    return matchErr;
  if (rule.exclude !== undefined && !Array.isArray(rule.exclude))
    return "exclude 须为数组";
  for (const ex of rule.exclude ?? []) {
    const e = checkMatch(ex);
    if (e)
      return `exclude: ${e}`;
  }
  if ((rule.tier === "community" || rule.tier === "plugin") && !hasHost(rule.match))
    return "社区规则必须限定 host 或 pageHost";
  const a = rule.action;
  switch (a.kind) {
    case "resource":
      if (!RESOURCE_TYPES.has(a.type))
        return "resource.type 非法";
      break;
    case "ignore":
      break;
    case "strip-params":
      if (!Array.isArray(a.params))
        return "params 须为数组";
      if (!hasHost(rule.match) && rule.tier !== "builtin" && rule.tier !== "official" && rule.tier !== "local")
        return "全局 strip-params 仅允许 builtin / official / local";
      break;
    case "filename":
      if (!Array.isArray(a.extFromQuery))
        return "extFromQuery 须为数组";
      break;
    case "track":
      if (!isSafeRegex(a.pattern))
        return "track.pattern 不安全";
      if (!Number.isInteger(a.group) || a.group < 0)
        return "track.group 非法";
      if (!Array.isArray(a.audio))
        return "track.audio 须为数组";
      break;
    case "extract": {
      if (!a.fields || typeof a.fields !== "object")
        return "fields 缺失";
      const err = checkEmit(a.emit, new Set(Object.keys(a.fields)), rule.tier);
      if (err)
        return err;
      break;
    }
    case "dom": {
      const sel = checkSelector(a.selector);
      if (sel)
        return sel;
      if (typeof a.attr !== "string")
        return "attr 缺失";
      const err = checkEmit(a.emit, new Set(["value", "text", "page"]), rule.tier);
      if (err)
        return err;
      break;
    }
    case "manifest":
      if (a.path !== undefined && typeof a.path !== "string")
        return "manifest.path 须为字符串";
      break;
    case "mirror":
      if (!Array.isArray(a.hosts) || a.hosts.length < 2)
        return "mirror.hosts 至少两个";
      for (const h of a.hosts) {
        if (typeof h !== "string" || !parseHostPattern(h))
          return "mirror.hosts 非法";
      }
      if (rule.tier === "community") {
        const scope = [...rule.match.host ?? [], ...rule.match.pageHost ?? []].flatMap((p) => parseHostPattern(p) ?? []);
        for (const h of a.hosts) {
          const domain = parseHostPattern(h)?.domain ?? "";
          if (!scope.some((p) => hostMatchesPattern(domain, p)))
            return `社区规则的 mirror.hosts 必须在 match.host / pageHost 范围内: ${h}`;
        }
      }
      break;
    case "title":
    case "player": {
      const sel = checkSelector(a.selector);
      if (sel)
        return sel;
      if (a.kind === "title" && a.attr !== undefined && typeof a.attr !== "string")
        return "attr 须为字符串";
      if (a.kind === "player" && a.float !== "hide")
        return "player.float 非法";
      if (!hasHost(rule.match) && rule.tier !== "local")
        return "page 规则必须限定 host 或 pageHost";
      break;
    }
    case "headers": {
      if (rule.tier === "plugin")
        return "plugin 规则不得改写请求头";
      if (!a.set || typeof a.set !== "object" || Array.isArray(a.set))
        return "headers.set 缺失";
      const entries = Object.entries(a.set);
      if (entries.length === 0 || entries.length > 16)
        return "headers.set 数量非法";
      for (const [name, value] of entries) {
        if (!/^[a-z0-9-]{1,64}$/i.test(name))
          return "header 名非法";
        if (FORBIDDEN_RULE_HEADERS.has(name.toLowerCase()))
          return `不允许设置 ${name}`;
        if (typeof value !== "string" || value.length > 1024 || /[\r\n]/.test(value))
          return "header 值非法";
      }
      if (!hasHost(rule.match))
        return "headers 规则必须限定 host 或 pageHost";
      break;
    }
  }
  return null;
}
function validatePack(pack, expectedTier) {
  if (!pack || typeof pack !== "object")
    throw new PackRejectedError("不是对象");
  if (pack.format !== "fluxdown-sniff-pack")
    throw new PackRejectedError("format 错误");
  if (!(expectedTier in TIER_RANK))
    throw new PackRejectedError("expectedTier 非法");
  if (pack.packId !== expectedTier)
    throw new PackRejectedError("packId 与预期层级不符");
  if (!Number.isInteger(pack.engine) || pack.engine > RULE_ENGINE_VERSION)
    throw new PackRejectedError("engine 版本过新或非法");
  if (!Number.isInteger(pack.sequence) || pack.sequence < 0)
    throw new PackRejectedError("sequence 非法");
  if (!Array.isArray(pack.rules) || pack.rules.length > MAX_RULES_PER_PACK)
    throw new PackRejectedError("rules 非法或超过上限");
  const seen = new Set;
  const accepted = [];
  const rejected = [];
  for (const rule of pack.rules) {
    const id = typeof rule?.id === "string" ? rule.id : "";
    if (id && seen.has(id)) {
      rejected.push({ id, reason: "id 重复" });
      continue;
    }
    const reason = checkRule(rule, expectedTier);
    if (reason) {
      rejected.push({ id, reason });
      continue;
    }
    seen.add(id);
    accepted.push(rule);
  }
  return { pack: { ...pack, rules: accepted }, rejected };
}

// fluxDown/rules/engine.ts
function makeCtx(url, pageUrl, extra = {}) {
  const headers = {};
  for (const [k, v] of Object.entries(extra.headers ?? {}))
    headers[k.toLowerCase()] = v;
  return {
    url,
    host: hostOf(url),
    pageHost: hostOf(pageUrl),
    path: pathOf(url),
    ext: extractExtension(url),
    mime: (extra.mime ?? "").split(";")[0].trim().toLowerCase(),
    resourceType: extra.resourceType,
    status: extra.status,
    size: extra.size ?? 0,
    attachment: extra.attachment ?? false,
    headers
  };
}
function compileHosts(list) {
  const out = [];
  for (const p of list) {
    const parsed = parseHostPattern(p);
    if (parsed)
      out.push(parsed);
  }
  return out;
}
function compileMatch(m) {
  const preds = [];
  if (m.host) {
    const hs = compileHosts(m.host);
    preds.push((c) => c.host !== "" && hs.some((p) => hostMatchesPattern(c.host, p)));
  }
  if (m.pageHost) {
    const hs = compileHosts(m.pageHost);
    preds.push((c) => c.pageHost !== "" && hs.some((p) => hostMatchesPattern(c.pageHost, p)));
  }
  if (m.url) {
    const globs = m.url;
    preds.push((c) => globs.some((g) => urlGlobMatch(g, c.url)));
  }
  if (m.pathRegex !== undefined) {
    let re = null;
    try {
      re = new RegExp(m.pathRegex, "i");
    } catch {
      re = null;
    }
    preds.push((c) => re !== null && re.test(c.path));
  }
  if (m.ext) {
    const exts = new Set(m.ext.map((e) => e.toLowerCase()));
    preds.push((c) => c.ext !== "" && exts.has(c.ext));
  }
  if (m.hasExt !== undefined) {
    const want = m.hasExt;
    preds.push((c) => c.ext !== "" === want);
  }
  if (m.mime) {
    const specs = m.mime.map((s) => s.toLowerCase());
    preds.push((c) => c.mime !== "" && specs.some((s) => s.endsWith("*") ? c.mime.startsWith(s.slice(0, -1)) : c.mime === s));
  }
  if (m.resourceType) {
    const types = m.resourceType;
    preds.push((c) => c.resourceType !== undefined && types.includes(c.resourceType));
  }
  if (m.status) {
    const [lo, hi] = m.status;
    preds.push((c) => c.status !== undefined && c.status >= lo && c.status <= hi);
  }
  if (m.minSize !== undefined) {
    const min = m.minSize;
    preds.push((c) => c.size <= 0 || c.size >= min);
  }
  if (m.maxSize !== undefined) {
    const max = m.maxSize;
    preds.push((c) => c.size <= 0 || c.size <= max);
  }
  if (m.attachment !== undefined) {
    const want = m.attachment;
    preds.push((c) => c.attachment === want);
  }
  if (m.header) {
    const hs = m.header.map((h) => {
      let re = null;
      try {
        re = new RegExp(h.regex, "i");
      } catch {
        re = null;
      }
      return { name: h.name.toLowerCase(), re };
    });
    preds.push((c) => hs.every((h) => {
      const v = c.headers[h.name];
      return v !== undefined && h.re !== null && h.re.test(v);
    }));
  }
  return (c) => preds.every((p) => p(c));
}
function getPath(root, path) {
  let cur = root;
  for (const seg of path.split(".")) {
    if (cur === null || typeof cur !== "object")
      return;
    if (Array.isArray(cur)) {
      if (!/^\d+$/.test(seg))
        return;
      cur = cur[Number(seg)];
    } else {
      if (!Object.hasOwn(cur, seg))
        return;
      cur = cur[seg];
    }
  }
  return cur;
}
function render(t, fields) {
  let missing = false;
  const out = t.replace(/\$\{([^}]*)\}/g, (_m, key) => {
    if (!Object.hasOwn(fields, key)) {
      missing = true;
      return "";
    }
    return fields[key];
  });
  return missing ? null : out;
}
function resolveUrl(base, ref, bareQueryPrefix) {
  let out;
  if (ref.startsWith("http://") || ref.startsWith("https://")) {
    out = ref;
  } else if (ref.startsWith("/")) {
    try {
      out = new URL(base).origin + ref;
    } catch {
      return null;
    }
  } else if (bareQueryPrefix !== undefined) {
    out = base + bareQueryPrefix + ref;
  } else {
    return null;
  }
  return out.startsWith("http") ? out : null;
}
function isoMs(s) {
  return s === undefined ? Number.NaN : Date.parse(s);
}
var GLOBAL_MATCH_KEYS = [
  "host",
  "pageHost",
  "url",
  "pathRegex",
  "ext",
  "hasExt",
  "mime",
  "resourceType",
  "status",
  "minSize",
  "maxSize",
  "attachment",
  "header"
];
function isGlobalMatch(r) {
  return GLOBAL_MATCH_KEYS.every((k) => r.match[k] === undefined) && (r.exclude ?? []).length === 0;
}
function compileRules(input) {
  const { packs, overrides, revocations, options } = input;
  const now = options.now;
  const revokeValid = revocations !== null && isoMs(revocations.expiresAt) > now;
  const listing = [];
  const active = [];
  let order = 0;
  const revocationOf = (rule) => {
    let found = null;
    for (const e of revocations?.entries ?? []) {
      if (e.ruleId !== rule.id)
        continue;
      if (e.versions !== "*" && !(rule.version <= e.versions.max))
        continue;
      if (e.action === "hard")
        return "hard";
      found = "soft";
    }
    return found;
  };
  for (const rawPack of packs) {
    if (rawPack.engine > RULE_ENGINE_VERSION) {
      for (const rule of Array.isArray(rawPack.rules) ? rawPack.rules : []) {
        listing.push({ rule, status: "engine-too-new", reason: "需要更新扩展" });
      }
      continue;
    }
    let pack;
    try {
      pack = validatePack(rawPack, rawPack.packId).pack;
    } catch (e) {
      if (e instanceof PackRejectedError)
        continue;
      throw e;
    }
    let paused = null;
    if (pack.packId === "community") {
      if (!options.communityEnabled) {
        paused = { status: "disabled", reason: "社区规则已关闭" };
      } else if (pack.expiresAt !== undefined && !(isoMs(pack.expiresAt) > now)) {
        paused = { status: "expired", reason: "社区规则包已过期" };
      } else if (!revokeValid) {
        paused = { status: "expired", reason: "吊销列表缺失或已过期" };
      }
    }
    for (const rule of pack.rules) {
      const ov = overrides[rule.id];
      const rev = revocationOf(rule);
      if (rev === "hard") {
        listing.push({ rule, status: "hard-revoked", reason: "已被撤回" });
        continue;
      }
      if (paused) {
        listing.push({ rule, status: paused.status, reason: paused.reason });
        continue;
      }
      if (rev === "soft" && !(ov?.enabled === true && ov.ackRevocation === revocations?.sequence)) {
        listing.push({ rule, status: "soft-revoked", reason: "已被撤回（可手动确认启用）" });
        continue;
      }
      const enabled = ov ? ov.enabled : rule.enabled !== false;
      if (!enabled) {
        listing.push({ rule, status: "disabled" });
        continue;
      }
      listing.push({ rule, status: "active" });
      active.push({ rule, order: order++ });
    }
  }
  active.sort((a, b) => TIER_RANK[a.rule.tier] - TIER_RANK[b.rule.tier] || (b.rule.priority ?? 0) - (a.rule.priority ?? 0) || a.order - b.order);
  const toC = (rule) => {
    const main = compileMatch(rule.match);
    const ex = (rule.exclude ?? []).map(compileMatch);
    return {
      ref: { id: rule.id, version: rule.version, tier: rule.tier },
      rule,
      matches: (c) => main(c) && !ex.some((p) => p(c))
    };
  };
  const byKind = (...kinds) => active.filter((a) => kinds.includes(a.rule.action.kind)).map((a) => toC(a.rule));
  const responseRules = byKind("resource", "ignore");
  const stripRules = byKind("strip-params");
  const filenameRules = byKind("filename");
  const trackRules = byKind("track");
  const bodyRules = byKind("extract", "manifest");
  const domRuleList = byKind("dom");
  const pageRules = byKind("title", "player");
  const headerRules = byKind("headers");
  const mirrorRules = byKind("mirror");
  const known = new Set;
  for (const c of responseRules) {
    if (c.rule.action.kind !== "resource")
      continue;
    for (const e of c.rule.match.ext ?? [])
      known.add(e.toLowerCase());
  }
  const communityScope = new Map;
  for (const { rule } of active) {
    if (rule.tier === "community") {
      communityScope.set(rule.id, compileHosts([...rule.match.host ?? [], ...rule.match.pageHost ?? []]));
    }
  }
  const emitAllowed = (rule, url) => {
    const scope = communityScope.get(rule.id);
    if (scope === undefined)
      return true;
    const host = hostOf(url);
    return host !== "" && scope.some((p) => hostMatchesPattern(host, p));
  };
  const globalStrip = new Set;
  const scopedStrip = [];
  for (const c of stripRules) {
    if (isGlobalMatch(c.rule)) {
      const a = c.rule.action;
      if (a.kind === "strip-params")
        for (const p of a.params)
          globalStrip.add(p.toLowerCase());
    } else {
      scopedStrip.push(c);
    }
  }
  const trackRegex = new Map;
  for (const c of trackRules) {
    const a = c.rule.action;
    if (a.kind !== "track")
      continue;
    try {
      trackRegex.set(c.rule.id, new RegExp(a.pattern, "i"));
    } catch {
      trackRegex.set(c.rule.id, null);
    }
  }
  const classify = (url, mime) => {
    const c = makeCtx(url, "", { mime });
    const resources = responseRules.filter((r) => r.rule.action.kind === "resource");
    const typeOf = (r) => r.rule.action.type;
    for (const r of resources) {
      if (r.rule.match.mime && r.matches(c))
        return typeOf(r);
    }
    for (const r of resources) {
      if (!r.rule.match.mime && r.rule.match.ext && r.matches(c))
        return typeOf(r);
    }
    return "other";
  };
  const emitOne = (spec, fields) => {
    let url;
    if (typeof spec.url === "string") {
      url = render(spec.url, fields);
    } else {
      const base = render(spec.url.resolve.base, fields);
      const ref = render(spec.url.resolve.ref, fields);
      url = base === null || ref === null ? null : resolveUrl(base, ref, spec.url.resolve.bareQueryPrefix);
    }
    if (url === null)
      return null;
    const out = { mode: spec.mode, url, type: spec.type ?? classify(url) };
    if (spec.filename !== undefined) {
      const f = render(spec.filename, fields);
      if (f !== null && f !== "")
        out.filename = f;
    }
    if (spec.quality !== undefined) {
      const q = render(spec.quality, fields);
      if (q !== null && q !== "")
        out.quality = q;
    }
    return out;
  };
  const scalarFields = (el, defs) => {
    const out = {};
    for (const [name, path] of Object.entries(defs)) {
      const v = getPath(el, path);
      if (typeof v === "string")
        out[name] = v;
      else if (typeof v === "number" || typeof v === "boolean" || typeof v === "bigint")
        out[name] = String(v);
    }
    return out;
  };
  const trackFromUrlHint = (url) => {
    let hint;
    try {
      hint = decodeURIComponent(url).toLowerCase();
    } catch {
      hint = url.toLowerCase();
    }
    if (hint.includes("audio/") || hint.includes("mime=audio"))
      return "audio";
    if (hint.includes("video/") || hint.includes("mime=video"))
      return "video";
    return null;
  };
  return {
    classifyResponse(i) {
      const c = makeCtx(i.url, i.pageUrl, {
        mime: i.mime,
        size: i.size,
        status: i.status,
        headers: i.headers,
        attachment: i.attachment,
        resourceType: i.resourceType
      });
      for (const r of responseRules) {
        if (r.rule.classifyOnly)
          continue;
        if (r.rule.requires === "sniffImages" && !options.sniffImages)
          continue;
        if (!r.matches(c))
          continue;
        const a = r.rule.action;
        if (a.kind === "ignore")
          return { decision: "ignore", rule: r.ref };
        if (a.kind === "resource") {
          return { decision: "resource", type: a.type, confidence: a.confidence, rule: r.ref };
        }
      }
      return { decision: "none" };
    },
    classify,
    isIgnored(url, pageUrl, attachment) {
      const c = makeCtx(url, pageUrl, { attachment });
      for (const r of responseRules) {
        if (r.rule.action.kind === "ignore" && r.matches(c))
          return r.ref;
      }
      return null;
    },
    dedupeKey(url, pageUrl) {
      try {
        const u = new URL(url);
        u.hash = "";
        const strip = new Set(globalStrip);
        if (scopedStrip.length > 0) {
          const c = makeCtx(url, pageUrl);
          for (const r of scopedStrip) {
            const a = r.rule.action;
            if (a.kind === "strip-params" && r.matches(c)) {
              for (const p of a.params)
                strip.add(p.toLowerCase());
            }
          }
        }
        const del = [];
        u.searchParams.forEach((_v, k) => {
          if (strip.has(k.toLowerCase()))
            del.push(k);
        });
        for (const k of del)
          u.searchParams.delete(k);
        u.searchParams.sort();
        return u.toString();
      } catch {
        return url;
      }
    },
    fileExtension(url, pageUrl) {
      const fromPath = extractExtension(url);
      if (fromPath)
        return fromPath;
      const c = makeCtx(url, pageUrl);
      for (const r of filenameRules) {
        const a = r.rule.action;
        if (a.kind === "filename" && r.matches(c)) {
          return extractExtension(url, a.extFromQuery, known);
        }
      }
      return "";
    },
    trackKind(input) {
      const mime = (input.mime ?? "").toLowerCase();
      if (mime.startsWith("audio/"))
        return "audio";
      const c = makeCtx(input.url, input.pageUrl, { mime: input.mime });
      let hostHit = false;
      for (const r of trackRules) {
        const a = r.rule.action;
        if (a.kind !== "track" || !r.matches(c))
          continue;
        hostHit = true;
        const m = (input.filename || input.url).match(trackRegex.get(r.rule.id) ?? /$^/);
        const g = trackRegex.get(r.rule.id) ? m?.[a.group] : undefined;
        if (g !== undefined) {
          if (a.audio.includes(g))
            return "audio";
          if (!a.video || a.video.includes(g))
            return "video";
        }
        if (a.fallback !== "none")
          return a.fallback;
      }
      if (mime.startsWith("video/") && !hostHit)
        return "video";
      return trackFromUrlHint(input.url);
    },
    bodyWatchers(pageUrl) {
      const c = makeCtx(pageUrl, pageUrl);
      const out = [];
      for (const r of bodyRules) {
        const m = r.rule.match;
        if (m.pageHost && !compileMatch({ pageHost: m.pageHost })(c))
          continue;
        out.push({ rule: r.ref, url: m.url, host: m.host, pathRegex: m.pathRegex });
      }
      return out;
    },
    extractFromBody(url, pageUrl, json) {
      const c = makeCtx(url, pageUrl);
      const out = [];
      for (const r of bodyRules) {
        const a = r.rule.action;
        if (a.kind !== "extract" || !r.matches(c))
          continue;
        if (a.when && !a.when.every((w) => getPath(json, w.path) === w.equals))
          continue;
        let elements;
        if (a.each !== undefined) {
          const arr = getPath(json, a.each);
          if (!Array.isArray(arr))
            continue;
          elements = arr;
        } else {
          elements = [json];
        }
        const emits = [];
        for (const el of elements) {
          const e = emitOne(a.emit, scalarFields(el, a.fields));
          if (e && emitAllowed(r.ref, e.url))
            emits.push(e);
        }
        if (emits.length > 0)
          out.push({ rule: r.ref, emits });
      }
      return out;
    },
    manifestsFromBody(url, pageUrl, json) {
      const c = makeCtx(url, pageUrl);
      const out = [];
      for (const r of bodyRules) {
        const a = r.rule.action;
        if (a.kind !== "manifest" || !r.matches(c))
          continue;
        const node = a.path ? getPath(json, a.path) : json;
        if (node !== undefined && node !== null)
          out.push(node);
      }
      return out;
    },
    domRules(pageUrl) {
      const c = makeCtx(pageUrl, pageUrl);
      const out = [];
      for (const r of domRuleList) {
        const a = r.rule.action;
        if (a.kind === "dom" && r.matches(c)) {
          out.push({ rule: r.ref, selector: a.selector, attr: a.attr, emit: a.emit });
        }
      }
      return out;
    },
    pageHints(pageUrl) {
      const c = makeCtx(pageUrl, pageUrl);
      const hints = { titles: [], players: [] };
      for (const r of pageRules) {
        if (!r.matches(c))
          continue;
        const a = r.rule.action;
        if (a.kind === "title")
          hints.titles.push(a.attr ? { selector: a.selector, attr: a.attr } : { selector: a.selector });
        else if (a.kind === "player")
          hints.players.push({ selector: a.selector });
      }
      return hints;
    },
    requestHeaders(url, pageUrl) {
      const c = makeCtx(url, pageUrl);
      const out = {};
      for (const r of headerRules) {
        const a = r.rule.action;
        if (a.kind !== "headers" || !r.matches(c))
          continue;
        for (const [name, value] of Object.entries(a.set)) {
          const lower = name.toLowerCase();
          if (!(lower in out))
            out[lower] = value;
        }
      }
      return out;
    },
    mirrorGroups() {
      const groups = [];
      for (const r of mirrorRules) {
        const a = r.rule.action;
        if (a.kind === "mirror")
          groups.push([...a.hosts]);
      }
      return groups;
    },
    renderDomEmit(rule, emit, fields) {
      const e = emitOne(emit, { value: fields.value, text: fields.text, page: fields.page });
      return e && emitAllowed(rule, e.url) ? e : null;
    },
    listRules() {
      return listing;
    },
    knownExtensions() {
      return known;
    }
  };
}
var BUILTIN_PACK = builtin_default;
export {
  BUILTIN_PACK,
  PackRejectedError,
  RULE_ENGINE_VERSION,
  compileRules,
  hostMatchesPattern,
  parseHostPattern,
  validatePack
};
