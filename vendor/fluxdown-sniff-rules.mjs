// 由 FluxDown 仓库 scripts/sniff-rules/sync-repo.ts vendor 生成，勿手改。
// 源：fluxDown/rules/{schema,validate,engine,glob,url}.ts 与 builtin.json。
// fluxDown/rules/builtin.json
var builtin_default = {
  format: "fluxdown-sniff-pack",
  packId: "builtin",
  sequence: 2,
  engine: 1,
  issuedAt: "2026-10-18T00:00:00Z",
  rules: [
    {
      id: "builtin.ext.video",
      version: 2,
      tier: "builtin",
      title: "按扩展名识别视频",
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
          "m4v",
          "3gp",
          "mpg",
          "mpeg",
          "f4v",
          "vob",
          "ogv",
          "rmvb",
          "rm",
          "asf",
          "m2ts",
          "mts",
          "divx"
        ]
      },
      action: {
        kind: "resource",
        type: "video"
      }
    },
    {
      id: "builtin.ext.audio",
      version: 2,
      tier: "builtin",
      title: "按扩展名识别音频",
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
          "alac",
          "aiff",
          "mka",
          "weba",
          "m4b"
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
      title: "按扩展名识别文档",
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
      version: 2,
      tier: "builtin",
      title: "按扩展名识别压缩包 / 镜像",
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
          "zst",
          "cab",
          "tgz",
          "tbz2",
          "txz",
          "lzma",
          "jar"
        ]
      },
      action: {
        kind: "resource",
        type: "archive"
      }
    },
    {
      id: "builtin.ext.image",
      version: 2,
      tier: "builtin",
      title: "按扩展名识别图片（需开启图片嗅探）",
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
      version: 2,
      tier: "builtin",
      title: "按扩展名识别安装包 / 可执行文件",
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
      title: "按扩展名识别种子文件",
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
      title: "按扩展名识别流媒体清单 / 分片",
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
      version: 2,
      tier: "builtin",
      title: "按扩展名识别字幕",
      stage: "response",
      priority: 20,
      match: {
        ext: [
          "vtt",
          "srt",
          "ass",
          "ssa",
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
      version: 2,
      tier: "builtin",
      title: "按 MIME 识别视频",
      stage: "response",
      priority: 10,
      match: {
        mime: [
          "video/*",
          "application/x-matroska"
        ]
      },
      action: {
        kind: "resource",
        type: "video"
      }
    },
    {
      id: "builtin.mime.audio",
      version: 2,
      tier: "builtin",
      title: "按 MIME 识别音频",
      stage: "response",
      priority: 10,
      match: {
        mime: [
          "audio/*",
          "application/ogg"
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
      title: "按 MIME 识别流媒体清单 / 分片",
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
      title: "按 MIME 识别图片（需开启图片嗅探）",
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
      version: 2,
      tier: "builtin",
      title: "按 MIME 归类文档（仅分类）",
      stage: "response",
      priority: 10,
      classifyOnly: true,
      match: {
        mime: [
          "application/pdf",
          "application/msword",
          "application/epub+zip",
          "text/csv",
          "application/vnd.openxmlformats-officedocument.*",
          "application/vnd.ms-word*",
          "application/vnd.ms-excel*",
          "application/vnd.ms-powerpoint*"
        ]
      },
      action: {
        kind: "resource",
        type: "document"
      }
    },
    {
      id: "builtin.mime.classify.archive",
      version: 2,
      tier: "builtin",
      title: "按 MIME 归类压缩包（仅分类）",
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
          "application/zstd",
          "application/x-zip-compressed",
          "application/vnd.rar"
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
      title: "按 MIME 归类安装包（仅分类）",
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
      title: "按 MIME 归类种子（仅分类）",
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
      title: "按 MIME 归类字幕（仅分类）",
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
      version: 2,
      tier: "builtin",
      title: "忽略统计 / 广告域名请求",
      stage: "response",
      priority: 30,
      exclude: [
        {
          attachment: true
        },
        {
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
            "odp",
            "zip",
            "rar",
            "7z",
            "tar",
            "gz",
            "bz2",
            "xz",
            "iso",
            "zst",
            "cab",
            "tgz",
            "tbz2",
            "txz",
            "lzma",
            "jar",
            "img",
            "z",
            "lz",
            "exe",
            "msi",
            "dmg",
            "deb",
            "rpm",
            "appimage",
            "apk",
            "ipa",
            "flatpak",
            "snap",
            "torrent"
          ]
        },
        {
          mime: [
            "application/pdf",
            "application/zip",
            "application/x-bittorrent"
          ]
        }
      ],
      match: {
        host: [
          "google-analytics.com",
          "googletagmanager.com",
          "analytics.google.com",
          "doubleclick.net",
          "googlesyndication.com",
          "googleadservices.com",
          "adservice.google.com",
          "connect.facebook.net",
          "hotjar.com",
          "clarity.ms",
          "mixpanel.com",
          "segment.io",
          "segment.com",
          "amplitude.com",
          "sentry.io",
          "bugsnag.com",
          "newrelic.com",
          "nr-data.net",
          "moat.com",
          "adsrvr.org",
          "advertising.com",
          "criteo.com",
          "outbrain.com",
          "taboola.com",
          "adnxs.com",
          "cdn.mxpnl.com",
          "stats.wp.com",
          "pixel.wp.com",
          "bat.bing.com",
          "sb.scorecardresearch.com",
          "b.scorecardresearch.com"
        ]
      },
      action: {
        kind: "ignore"
      }
    },
    {
      id: "builtin.noise.hosts",
      version: 2,
      tier: "builtin",
      title: "忽略追踪像素专用主机",
      stage: "response",
      priority: 30,
      match: {
        host: [
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
      id: "builtin.noise.google-pagead",
      version: 1,
      tier: "builtin",
      title: "忽略 Google 广告路径",
      stage: "response",
      priority: 30,
      exclude: [
        {
          attachment: true
        }
      ],
      match: {
        host: [
          "google.com"
        ],
        pathRegex: "^/pagead(?:/|$)"
      },
      action: {
        kind: "ignore"
      }
    },
    {
      id: "builtin.noise.facebook-tr",
      version: 1,
      tier: "builtin",
      title: "忽略 Facebook 追踪像素路径",
      stage: "response",
      priority: 30,
      exclude: [
        {
          attachment: true
        }
      ],
      match: {
        host: [
          "facebook.com"
        ],
        pathRegex: "^/tr(?:/|$)"
      },
      action: {
        kind: "ignore"
      }
    },
    {
      id: "builtin.noise.fbcdn-signals",
      version: 1,
      tier: "builtin",
      title: "忽略 Facebook 信号上报路径",
      stage: "response",
      priority: 30,
      exclude: [
        {
          attachment: true
        }
      ],
      match: {
        host: [
          "fbcdn.net"
        ],
        pathRegex: "^/signals(?:/|$)"
      },
      action: {
        kind: "ignore"
      }
    },
    {
      id: "builtin.noise.paths",
      version: 2,
      tier: "builtin",
      title: "忽略站点接口 / 静态资源 / 埋点路径",
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
            "m4v",
            "3gp",
            "mpg",
            "mpeg",
            "f4v",
            "vob",
            "ogv",
            "rmvb",
            "rm",
            "asf",
            "m2ts",
            "mts",
            "divx",
            "ts",
            "mp3",
            "flac",
            "wav",
            "aac",
            "ogg",
            "wma",
            "m4a",
            "opus",
            "alac",
            "aiff",
            "mka",
            "weba",
            "m4b",
            "ape",
            "pdf",
            "doc",
            "docx",
            "xls",
            "xlsx",
            "ppt",
            "pptx",
            "rtf",
            "epub",
            "mobi",
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
            "zst",
            "cab",
            "tgz",
            "tbz2",
            "txz",
            "lzma",
            "jar",
            "img",
            "z",
            "lz",
            "exe",
            "msi",
            "dmg",
            "deb",
            "rpm",
            "appimage",
            "apk",
            "ipa",
            "flatpak",
            "snap",
            "torrent",
            "m3u8",
            "m3u",
            "mpd",
            "m4s",
            "vtt",
            "srt",
            "ass",
            "ssa",
            "sup",
            "lrc",
            "sub",
            "idx"
          ]
        },
        {
          mime: [
            "video/*",
            "audio/*",
            "application/x-matroska",
            "application/ogg",
            "application/vnd.apple.mpegurl",
            "application/x-mpegurl",
            "application/mpegurl",
            "application/octet-stream-m3u8",
            "audio/mpegurl",
            "audio/x-mpegurl",
            "application/dash+xml",
            "application/m4s",
            "application/pdf",
            "application/zip",
            "application/x-bittorrent"
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
      id: "builtin.normalize.strip",
      version: 2,
      tier: "builtin",
      title: "去重时忽略缓存破坏与广告追踪参数",
      stage: "normalize",
      match: {},
      action: {
        kind: "strip-params",
        params: [
          "_",
          "cb",
          "nocache",
          "cache",
          "rand",
          "random",
          "bust",
          "utm_source",
          "utm_medium",
          "utm_campaign",
          "utm_term",
          "utm_content",
          "fbclid",
          "gclid",
          "msclkid",
          "twclid"
        ]
      }
    },
    {
      id: "builtin.normalize.query-ext",
      version: 1,
      tier: "builtin",
      title: "从 format / ext / fm 查询参数推断扩展名",
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
    },
    {
      id: "builtin.ext.video-ambiguous",
      version: 1,
      tier: "builtin",
      title: "按扩展名识别视频（歧义扩展名：ts；脚本 / 文本类 MIME 不算）",
      stage: "response",
      priority: 20,
      match: {
        ext: [
          "ts"
        ]
      },
      action: {
        kind: "resource",
        type: "video"
      },
      exclude: [
        {
          mime: [
            "text/*",
            "application/javascript",
            "application/x-javascript",
            "application/json",
            "application/typescript",
            "application/x-typescript"
          ]
        }
      ]
    },
    {
      id: "builtin.ext.audio-ambiguous",
      version: 1,
      tier: "builtin",
      title: "按扩展名识别音频（歧义扩展名：ape；脚本 / 文本类 MIME 不算）",
      stage: "response",
      priority: 20,
      match: {
        ext: [
          "ape"
        ]
      },
      action: {
        kind: "resource",
        type: "audio"
      },
      exclude: [
        {
          mime: [
            "text/*",
            "application/javascript",
            "application/x-javascript",
            "application/json",
            "application/typescript",
            "application/x-typescript"
          ]
        }
      ]
    },
    {
      id: "builtin.ext.archive-ambiguous",
      version: 1,
      tier: "builtin",
      title: "按扩展名识别压缩包 / 镜像（歧义扩展名：img / z / lz；脚本 / 文本类 MIME 不算）",
      stage: "response",
      priority: 20,
      match: {
        ext: [
          "img",
          "z",
          "lz"
        ]
      },
      action: {
        kind: "resource",
        type: "archive"
      },
      exclude: [
        {
          mime: [
            "text/*",
            "application/javascript",
            "application/x-javascript",
            "application/json",
            "application/typescript",
            "application/x-typescript"
          ]
        }
      ]
    },
    {
      id: "builtin.ext.image-ambiguous",
      version: 1,
      tier: "builtin",
      title: "按扩展名识别图片（需开启图片嗅探）（歧义扩展名：raw；脚本 / 文本类 MIME 不算）",
      stage: "response",
      priority: 20,
      requires: "sniffImages",
      match: {
        ext: [
          "raw"
        ]
      },
      action: {
        kind: "resource",
        type: "image"
      },
      exclude: [
        {
          mime: [
            "text/*",
            "application/javascript",
            "application/x-javascript",
            "application/json",
            "application/typescript",
            "application/x-typescript"
          ]
        }
      ]
    },
    {
      id: "builtin.ext.executable-ambiguous",
      version: 1,
      tier: "builtin",
      title: "按扩展名识别安装包 / 可执行文件（歧义扩展名：snap；脚本 / 文本类 MIME 不算）",
      stage: "response",
      priority: 20,
      match: {
        ext: [
          "snap"
        ]
      },
      action: {
        kind: "resource",
        type: "executable"
      },
      exclude: [
        {
          mime: [
            "text/*",
            "application/javascript",
            "application/x-javascript",
            "application/json",
            "application/typescript",
            "application/x-typescript"
          ]
        }
      ]
    },
    {
      id: "builtin.ext.subtitle-ambiguous",
      version: 1,
      tier: "builtin",
      title: "按扩展名识别字幕（歧义扩展名：sub / idx；脚本 / 文本类 MIME 不算）",
      stage: "response",
      priority: 20,
      match: {
        ext: [
          "sub",
          "idx"
        ]
      },
      action: {
        kind: "resource",
        type: "subtitle"
      },
      exclude: [
        {
          mime: [
            "text/html",
            "text/javascript",
            "text/css",
            "application/javascript",
            "application/x-javascript",
            "application/json"
          ]
        }
      ]
    }
  ]
};
// fluxDown/rules/official.json
var official_default = {
  format: "fluxdown-sniff-pack",
  packId: "official",
  sequence: 1,
  engine: 1,
  issuedAt: "2026-10-18T06:24:42.796Z",
  rules: [
    {
      id: "official.bilibili.track",
      version: 1,
      tier: "official",
      title: "哔哩哔哩：按 m4s 分片编号区分音轨 / 视频轨（CDN 域名）",
      stage: "track",
      match: {
        host: [
          "bilibili.com",
          "bilivideo.com",
          "bilivideo.cn",
          "acgvideo.com"
        ]
      },
      action: {
        kind: "track",
        source: "filenameOrUrl",
        pattern: "[-_](\\d{4,6})\\.m4s(?:[?#]|$)",
        group: 1,
        audio: [
          "30216",
          "30232",
          "30280",
          "30250",
          "30251"
        ],
        fallback: "video"
      }
    },
    {
      id: "official.bilibili.track-page",
      version: 1,
      tier: "official",
      title: "哔哩哔哩：按 m4s 分片编号区分音轨 / 视频轨（站内页面）",
      stage: "track",
      match: {
        pageHost: [
          "bilibili.com",
          "bilivideo.com",
          "bilivideo.cn",
          "acgvideo.com"
        ]
      },
      action: {
        kind: "track",
        source: "filenameOrUrl",
        pattern: "[-_](\\d{4,6})\\.m4s(?:[?#]|$)",
        group: 1,
        audio: [
          "30216",
          "30232",
          "30280",
          "30250",
          "30251"
        ],
        fallback: "video"
      }
    },
    {
      id: "official.douyin.title",
      version: 1,
      tier: "official",
      title: "抖音：视频描述作为文件名",
      stage: "page",
      match: {
        pageHost: [
          "douyin.com"
        ]
      },
      action: {
        kind: "title",
        selector: '[data-e2e="video-desc"]'
      }
    },
    {
      id: "official.lanzou.extract",
      version: 1,
      tier: "official",
      title: "蓝奏云：从 ajaxm.php 响应提取直链",
      stage: "body",
      match: {
        url: [
          "*/ajaxm.php*"
        ]
      },
      action: {
        kind: "extract",
        when: [
          {
            path: "zt",
            equals: 1
          }
        ],
        fields: {
          dom: "dom",
          url: "url",
          name: "inf"
        },
        emit: {
          mode: "preempt",
          url: {
            resolve: {
              base: "${dom}",
              ref: "${url}",
              bareQueryPrefix: "/file/"
            }
          },
          filename: "${name}"
        }
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
  return /[A-Z]/.test(s) ? s.replace(/[A-Z]+/g, (m) => m.toLowerCase()) : s;
}
function compileGlob(pattern) {
  const p = asciiLower(pattern);
  if (!p.includes("*"))
    return (t) => t === p;
  const parts = p.split("*");
  const n = parts.length;
  if (n === 2) {
    const [head, tail] = parts;
    if (head === "" && tail === "")
      return () => true;
    if (head === "")
      return (t) => t.endsWith(tail);
    if (tail === "")
      return (t) => t.startsWith(head);
    return (t) => t.length >= head.length + tail.length && t.startsWith(head) && t.endsWith(tail);
  }
  if (n === 3 && parts[0] === "" && parts[2] === "" && parts[1] !== "") {
    const mid = parts[1];
    return (t) => t.includes(mid);
  }
  return (t) => {
    let pos = 0;
    for (let i = 0;i < n; i++) {
      const part = parts[i];
      if (part === "")
        continue;
      if (i === 0) {
        if (!t.startsWith(part))
          return false;
        pos = part.length;
      } else if (i === n - 1) {
        if (t.length - pos < part.length || !t.endsWith(part))
          return false;
      } else {
        const idx = t.indexOf(part, pos);
        if (idx < 0)
          return false;
        pos = idx + part.length;
      }
    }
    return true;
  };
}
function parseHostPattern(pattern) {
  const raw = pattern.trim();
  const exact = raw.startsWith("=");
  const body = exact ? raw.slice(1) : raw;
  if (body.trim().startsWith("*."))
    return null;
  const domain = normalizeDomain(body);
  return domain ? { domain, suffix: `.${domain}`, exact } : null;
}
function hostMatchesLower(host, p) {
  return p.exact ? host === p.domain : host === p.domain || host.endsWith(p.suffix);
}
function hostMatchesPattern(host, p) {
  return hostMatchesLower(host.toLowerCase(), p);
}

// fluxDown/rules/regex-safety.ts
var MAX_REGEX_LEN = 256;
var REGEX_INPUT_CAP = 2048;
var MAX_UNBOUNDED_QUANTIFIERS = 4;
var BOUNDED_MAX = 100;
var SET_SIZE = 129;
var NON_ASCII = 128;

class Unsupported extends Error {
}
function emptySet() {
  return new Uint8Array(SET_SIZE);
}
function fullSet() {
  return new Uint8Array(SET_SIZE).fill(1);
}
function addRange(set, lo, hi) {
  for (let c = lo;c <= hi; c++)
    set[c < NON_ASCII ? c : NON_ASCII] = 1;
}
function invert(set) {
  const out = emptySet();
  for (let i = 0;i < SET_SIZE; i++)
    out[i] = set[i] ? 0 : 1;
  return out;
}
function overlaps(a, b) {
  for (let i = 0;i < SET_SIZE; i++)
    if (a[i] && b[i])
      return true;
  return false;
}
function foldCase(set) {
  for (let c = 65;c <= 90; c++) {
    if (set[c] || set[c + 32]) {
      set[c] = 1;
      set[c + 32] = 1;
    }
  }
}
function classEscapeSet(letter) {
  const set = emptySet();
  switch (letter) {
    case "d":
    case "D":
      addRange(set, 48, 57);
      break;
    case "w":
    case "W":
      addRange(set, 48, 57);
      addRange(set, 65, 90);
      addRange(set, 97, 122);
      set[95] = 1;
      break;
    case "s":
    case "S":
      for (const c of [9, 10, 11, 12, 13, 32])
        set[c] = 1;
      set[NON_ASCII] = 1;
      break;
    default:
      return null;
  }
  return letter === "D" || letter === "W" || letter === "S" ? invert(set) : set;
}
var HEX2 = /^[0-9a-fA-F]{2}/;
var HEX4 = /^[0-9a-fA-F]{4}/;
var BRACE_QUANT = /\{(\d+)(?:(,)(\d*))?\}/y;
var CONTROL_ESCAPES = { n: 10, r: 13, t: 9, f: 12, v: 11, "0": 0 };

class Parser {
  src;
  pos = 0;
  constructor(src) {
    this.src = src;
  }
  parse() {
    const alts = this.parseAlts();
    if (this.pos !== this.src.length)
      throw new Unsupported("trailing");
    return alts;
  }
  parseAlts() {
    const alts = [[]];
    while (this.pos < this.src.length) {
      const c = this.src[this.pos];
      if (c === ")")
        break;
      if (c === "|") {
        alts.push([]);
        this.pos++;
        continue;
      }
      const node = this.parseAtom();
      const { min, max } = this.parseQuantifier();
      alts[alts.length - 1].push({ node, min, max });
    }
    return alts;
  }
  parseQuantifier() {
    const c = this.src[this.pos];
    let min = 1;
    let max = 1;
    if (c === "*") {
      min = 0;
      max = Infinity;
      this.pos++;
    } else if (c === "+") {
      max = Infinity;
      this.pos++;
    } else if (c === "?") {
      min = 0;
      this.pos++;
    } else if (c === "{") {
      BRACE_QUANT.lastIndex = this.pos;
      const m = BRACE_QUANT.exec(this.src);
      if (m) {
        min = Number(m[1]);
        max = m[2] === undefined ? min : m[3] === "" ? Infinity : Number(m[3]);
        this.pos = BRACE_QUANT.lastIndex;
      }
    } else {
      return { min, max };
    }
    if (max > BOUNDED_MAX)
      max = Infinity;
    if (this.src[this.pos] === "?")
      this.pos++;
    return { min, max };
  }
  parseAtom() {
    const c = this.src[this.pos];
    switch (c) {
      case "(":
        return this.parseGroup();
      case "[":
        return this.parseClass();
      case "\\":
        return this.parseEscape();
      case ".": {
        this.pos++;
        const set = fullSet();
        set[10] = 0;
        set[13] = 0;
        return { k: "char", set, lit: null };
      }
      case "^":
      case "$":
        this.pos++;
        return { k: "zero" };
      default:
        this.pos++;
        return this.literal(c.charCodeAt(0));
    }
  }
  literal(code) {
    const set = emptySet();
    set[code < NON_ASCII ? code : NON_ASCII] = 1;
    foldCase(set);
    return { k: "char", set, lit: String.fromCharCode(code).toLowerCase() };
  }
  parseGroup() {
    this.pos++;
    if (this.src[this.pos] === "?") {
      const next = this.src[this.pos + 1];
      if (next === ":") {
        this.pos += 2;
      } else if (next === "<" && this.src[this.pos + 2] !== "=" && this.src[this.pos + 2] !== "!") {
        const close = this.src.indexOf(">", this.pos);
        if (close < 0)
          throw new Unsupported("named group");
        this.pos = close + 1;
      } else {
        throw new Unsupported("lookaround");
      }
    }
    const alts = this.parseAlts();
    if (this.src[this.pos] !== ")")
      throw new Unsupported("unclosed group");
    this.pos++;
    return { k: "group", alts };
  }
  readEscape(inClass) {
    this.pos++;
    const e = this.src[this.pos];
    if (e === undefined)
      throw new Unsupported("dangling escape");
    this.pos++;
    const cls = classEscapeSet(e);
    if (cls)
      return { set: cls };
    if (e === "b")
      return inClass ? { code: 8 } : "zero";
    if (e === "B" && !inClass)
      return "zero";
    if (e === "k" || e >= "1" && e <= "9")
      throw new Unsupported("backreference");
    const ctrl = CONTROL_ESCAPES[e];
    if (ctrl !== undefined)
      return { code: ctrl };
    if (e === "x") {
      const m = HEX2.exec(this.src.slice(this.pos, this.pos + 2));
      if (m) {
        this.pos += 2;
        return { code: parseInt(m[0], 16) };
      }
    }
    if (e === "u") {
      const m = HEX4.exec(this.src.slice(this.pos, this.pos + 4));
      if (m) {
        this.pos += 4;
        return { code: parseInt(m[0], 16) };
      }
    }
    if (e === "c") {
      const letter = this.src[this.pos];
      if (letter !== undefined && /[a-zA-Z]/.test(letter)) {
        this.pos++;
        return { code: letter.charCodeAt(0) % 32 };
      }
    }
    return { code: e.charCodeAt(0) };
  }
  parseEscape() {
    const r = this.readEscape(false);
    if (r === "zero")
      return { k: "zero" };
    if ("set" in r)
      return { k: "char", set: r.set, lit: null };
    return this.literal(r.code);
  }
  parseClass() {
    this.pos++;
    let negate = false;
    if (this.src[this.pos] === "^") {
      negate = true;
      this.pos++;
    }
    const set = emptySet();
    while (this.pos < this.src.length && this.src[this.pos] !== "]") {
      const a = this.classAtom();
      if (this.src[this.pos] === "-" && this.src[this.pos + 1] !== "]" && this.pos + 1 < this.src.length && "code" in a) {
        const save = this.pos;
        this.pos++;
        const b = this.classAtom();
        if ("code" in b) {
          addRange(set, Math.min(a.code, b.code), Math.max(a.code, b.code));
          continue;
        }
        this.pos = save;
      }
      if ("code" in a)
        set[a.code < NON_ASCII ? a.code : NON_ASCII] = 1;
      else
        for (let i = 0;i < SET_SIZE; i++)
          if (a.set[i])
            set[i] = 1;
    }
    if (this.src[this.pos] !== "]")
      throw new Unsupported("unclosed class");
    this.pos++;
    foldCase(set);
    return { k: "char", set: negate ? invert(set) : set, lit: null };
  }
  classAtom() {
    if (this.src[this.pos] === "\\") {
      const r = this.readEscape(true);
      if (r === "zero")
        throw new Unsupported("class escape");
      return r;
    }
    const code = this.src.charCodeAt(this.pos);
    this.pos++;
    return { code };
  }
}
function containsRepeat(alts) {
  return alts.some((seq) => seq.some((it) => it.max > 1 || it.node.k === "group" && containsRepeat(it.node.alts)));
}
function isPrefixFreeLiterals(alts) {
  const words = [];
  for (const seq of alts) {
    let w = "";
    for (const it of seq) {
      if (it.node.k !== "char" || it.node.lit === null || it.min !== 1 || it.max !== 1)
        return false;
      w += it.node.lit;
    }
    if (w === "")
      return false;
    words.push(w);
  }
  for (let i = 0;i < words.length; i++) {
    for (let j = 0;j < words.length; j++) {
      if (i !== j && words[j].startsWith(words[i]))
        return false;
    }
  }
  return true;
}
function analyze(alts, counter) {
  for (const seq of alts) {
    let run = [];
    for (const it of seq) {
      const { node, min, max } = it;
      if (node.k === "group") {
        if (max > 1) {
          if (max === Infinity && containsRepeat(node.alts))
            return "nested_quantifier";
          if (node.alts.length > 1 && !isPrefixFreeLiterals(node.alts))
            return "ambiguous_alternation";
        }
        const before = counter.n;
        const err = analyze(node.alts, counter);
        if (err)
          return err;
        if (max > 1 && max !== Infinity)
          counter.n += (counter.n - before) * (max - 1);
      }
      if (max === Infinity) {
        counter.n++;
        const set = node.k === "char" ? node.set : fullSet();
        if (run.some((r) => overlaps(r, set)))
          return "overlapping_quantifiers";
        run.push(set);
      } else if (node.k === "zero" || min === 0) {} else {
        run = [];
      }
      if (counter.n > MAX_UNBOUNDED_QUANTIFIERS)
        return "too_many_quantifiers";
    }
  }
  return null;
}
function regexProblem(pattern) {
  if (typeof pattern !== "string")
    return "not_string";
  if (pattern.length > MAX_REGEX_LEN)
    return "too_long";
  try {
    new RegExp(pattern, "i");
  } catch {
    return "syntax";
  }
  if (/\\[1-9]|\\k</.test(pattern))
    return "backreference";
  if (/\(\?(?:=|!|<=|<!)/.test(pattern))
    return "lookaround";
  try {
    const parser = new Parser(pattern);
    return analyze(parser.parse(), { n: 0 });
  } catch (e) {
    if (e instanceof Unsupported)
      return `unsupported_${e.message.replace(/\W+/g, "_")}`;
    throw e;
  }
}
function isSafeRegex(pattern) {
  return regexProblem(pattern) === null;
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
var ALLOWED_RULE_HEADERS = new Set([
  "referer",
  "origin",
  "user-agent",
  "accept",
  "accept-language",
  "x-requested-with"
]);

// fluxDown/rules/url.ts
function normalizeHost(hostname) {
  const h = hostname.toLowerCase();
  return h.endsWith(".") ? h.slice(0, -1) : h;
}
var EXT_RE = /^[a-z0-9]{1,10}$/;
function extensionOfPath(pathname) {
  let seg = pathname.slice(pathname.lastIndexOf("/") + 1);
  const semi = seg.indexOf(";");
  if (semi >= 0)
    seg = seg.slice(0, semi);
  const dot = seg.lastIndexOf(".");
  if (dot <= 0 || dot >= seg.length - 1)
    return "";
  const ext = seg.slice(dot + 1).toLowerCase();
  return EXT_RE.test(ext) ? ext : "";
}
var RAW_EXT_RE = /\.([a-zA-Z0-9]{1,10})(?:[?#;]|$)/;
function parseUrlParts(url) {
  try {
    const u = new URL(url);
    return { host: normalizeHost(u.hostname), path: u.pathname, ext: extensionOfPath(u.pathname) };
  } catch {
    const m = url.match(RAW_EXT_RE);
    return { host: "", path: "", ext: m ? m[1].toLowerCase() : "" };
  }
}
function hostOf(url) {
  try {
    return normalizeHost(new URL(url).hostname);
  } catch {
    return "";
  }
}
function extractExtension(url, queryKeys = [], known) {
  const fromPath = parseUrlParts(url).ext;
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
var MAX_SELECTOR_LEN = 512;
var MAX_RULE_JSON_LEN = 16 * 1024;
var MAX_URL_GLOBS = 64;
var MAX_EXTS = 256;
var MAX_MIMES = 64;
var MAX_HEADER_PREDICATES = 8;
var MAX_MIRROR_HOSTS = 16;
var MAX_EXTRACT_FIELDS = 32;
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

class PackRejectedError extends Error {
  code;
  constructor(message, code = "pack_invalid") {
    super(message);
    this.name = "PackRejectedError";
    this.code = code;
  }
}
function bad(code, detail, param) {
  return param === undefined ? { code, detail } : { code, detail, param };
}
function isStringArray(v) {
  return Array.isArray(v) && v.every((x) => typeof x === "string");
}
var ARRAY_LIMITS = { url: MAX_URL_GLOBS, ext: MAX_EXTS, mime: MAX_MIMES };
function checkMatch(m, scoped = false) {
  if (m === undefined)
    return null;
  if (typeof m !== "object" || m === null || Array.isArray(m))
    return bad("match_invalid", "match 不是对象");
  for (const key of ["host", "pageHost"]) {
    const list = m[key];
    if (list === undefined)
      continue;
    if (!Array.isArray(list))
      return bad("host_list_invalid", "host/pageHost 须为数组", key);
    for (const h of list) {
      const parsed = typeof h === "string" ? parseHostPattern(h) : null;
      if (parsed === null)
        return bad("host_invalid", `非法 host 模式: ${String(h)}`, String(h));
      if (scoped && !parsed.domain.includes("."))
        return bad("host_too_broad", `host 范围过宽（单标签域名）: ${String(h)}`, String(h));
    }
  }
  for (const key of ["url", "ext", "mime", "resourceType"]) {
    const list = m[key];
    if (list === undefined)
      continue;
    if (!isStringArray(list))
      return bad("string_array_required", `${key} 须为字符串数组`, key);
    const limit = key === "resourceType" ? undefined : ARRAY_LIMITS[key];
    if (limit !== undefined && list.length > limit)
      return bad("too_many", `${key} 最多 ${limit} 项`, key);
  }
  if (m.status !== undefined && !(Array.isArray(m.status) && m.status.length === 2 && m.status.every((n) => Number.isInteger(n))))
    return bad("status_invalid", "status 须为 [整数, 整数]", "status");
  for (const key of ["minSize", "maxSize"]) {
    const v = m[key];
    if (v !== undefined && !(typeof v === "number" && Number.isFinite(v) && v >= 0))
      return bad("size_invalid", `${key} 须为非负数`, key);
  }
  for (const key of ["hasExt", "attachment"]) {
    if (m[key] !== undefined && typeof m[key] !== "boolean")
      return bad("boolean_required", `${key} 须为布尔值`, key);
  }
  if (m.pathRegex !== undefined && !isSafeRegex(m.pathRegex))
    return bad("unsafe_regex", "pathRegex 不安全", "pathRegex");
  if (m.header !== undefined) {
    if (!Array.isArray(m.header))
      return bad("header_invalid", "header 须为数组", "header");
    if (m.header.length > MAX_HEADER_PREDICATES)
      return bad("too_many", `header 最多 ${MAX_HEADER_PREDICATES} 项`, "header");
    for (const h of m.header) {
      if (!h || typeof h.name !== "string" || !isSafeRegex(h.regex))
        return bad("unsafe_regex", "header 正则不安全", "header");
    }
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
    return bad("emit_missing", "emit 缺失");
  if (emit.mode !== "resource" && emit.mode !== "preempt")
    return bad("emit_mode_invalid", "emit.mode 非法");
  if (emit.mode === "preempt" && tier !== "builtin" && tier !== "official")
    return bad("preempt_forbidden", "preempt 仅允许 builtin / official");
  if (emit.type !== undefined && !RESOURCE_TYPES.has(emit.type))
    return bad("emit_type_invalid", "emit.type 非法");
  if (typeof emit.url !== "string" && !(emit.url && typeof emit.url === "object" && emit.url.resolve))
    return bad("emit_url_missing", "emit.url 缺失");
  for (const ref of emitRefs(emit)) {
    if (!allowed.has(ref))
      return bad("template_unknown_field", `模板引用了未定义字段: ${ref}`, ref);
  }
  return null;
}
function checkSelector(selector) {
  if (typeof selector !== "string" || selector.length === 0)
    return bad("selector_missing", "selector 缺失");
  if (selector.length > MAX_SELECTOR_LEN)
    return bad("selector_too_long", "selector 过长");
  if (typeof document !== "undefined") {
    try {
      document.createDocumentFragment().querySelector(selector);
    } catch {
      return bad("selector_invalid", "selector 非法");
    }
  }
  return null;
}
function hasHost(m) {
  return Array.isArray(m.host) && m.host.length > 0 || Array.isArray(m.pageHost) && m.pageHost.length > 0;
}
function checkRule(rule, expectedTier) {
  if (!rule || typeof rule !== "object")
    return bad("rule_invalid", "规则不是对象");
  if (typeof rule.id !== "string" || !ID_RE.test(rule.id))
    return bad("id_invalid", "id 非法");
  if (rule.tier === "plugin" && rule.id.length > 64)
    return bad("id_invalid", "id 非法");
  if (rule.tier !== expectedTier)
    return bad("tier_mismatch", "tier 与 packId 不符");
  if (!rule.id.startsWith(`${rule.tier}.`))
    return bad("id_prefix_mismatch", "id 前缀与 tier 不符");
  if (!Number.isInteger(rule.version) || rule.version < 1)
    return bad("version_invalid", "version 非法");
  if (!rule.match || typeof rule.match !== "object")
    return bad("match_missing", "match 缺失");
  if (!rule.action || typeof rule.action !== "object")
    return bad("action_missing", "action 缺失");
  const allowedKinds = STAGE_ACTIONS[rule.stage];
  if (!allowedKinds)
    return bad("stage_invalid", "stage 非法");
  if (!allowedKinds.includes(rule.action.kind))
    return bad("stage_action_mismatch", "stage 与 action 不匹配");
  if (rule.requires !== undefined && rule.requires !== "sniffImages")
    return bad("requires_invalid", "requires 非法");
  if (rule.title !== undefined && typeof rule.title !== "string")
    return bad("field_type", "title 须为字符串", "title");
  if (rule.enabled !== undefined && typeof rule.enabled !== "boolean")
    return bad("field_type", "enabled 须为布尔值", "enabled");
  if (rule.classifyOnly !== undefined && typeof rule.classifyOnly !== "boolean")
    return bad("field_type", "classifyOnly 须为布尔值", "classifyOnly");
  if (rule.priority !== undefined && !(typeof rule.priority === "number" && Number.isFinite(rule.priority)))
    return bad("field_type", "priority 须为数字", "priority");
  if (JSON.stringify(rule).length > MAX_RULE_JSON_LEN)
    return bad("rule_too_large", `单条规则不得超过 ${MAX_RULE_JSON_LEN / 1024} KB`);
  const scoped = rule.tier === "community" || rule.tier === "plugin";
  const matchErr = checkMatch(rule.match, scoped);
  if (matchErr)
    return matchErr;
  if (rule.exclude !== undefined && !Array.isArray(rule.exclude))
    return bad("exclude_invalid", "exclude 须为数组", "exclude");
  for (const ex of rule.exclude ?? []) {
    const e = checkMatch(ex);
    if (e)
      return { ...e, detail: `exclude: ${e.detail}` };
  }
  if (scoped && !hasHost(rule.match))
    return bad("scope_required", "社区规则必须限定 host 或 pageHost");
  const a = rule.action;
  switch (a.kind) {
    case "resource":
      if (!RESOURCE_TYPES.has(a.type))
        return bad("resource_type_invalid", "resource.type 非法", String(a.type));
      break;
    case "ignore":
      break;
    case "strip-params":
      if (!isStringArray(a.params))
        return bad("string_array_required", "params 须为字符串数组", "params");
      if (!hasHost(rule.match) && rule.tier !== "builtin" && rule.tier !== "official" && rule.tier !== "local")
        return bad("global_strip_forbidden", "全局 strip-params 仅允许 builtin / official / local");
      break;
    case "filename":
      if (!isStringArray(a.extFromQuery))
        return bad("string_array_required", "extFromQuery 须为字符串数组", "extFromQuery");
      break;
    case "track":
      if (!isSafeRegex(a.pattern))
        return bad("unsafe_regex", "track.pattern 不安全", "track.pattern");
      if (!Number.isInteger(a.group) || a.group < 0)
        return bad("track_group_invalid", "track.group 非法");
      if (!isStringArray(a.audio))
        return bad("string_array_required", "track.audio 须为字符串数组", "track.audio");
      if (a.video !== undefined && !isStringArray(a.video))
        return bad("string_array_required", "track.video 须为字符串数组", "track.video");
      if (a.fallback !== "video" && a.fallback !== "audio" && a.fallback !== "none")
        return bad("track_fallback_invalid", "track.fallback 非法");
      break;
    case "extract": {
      if (!a.fields || typeof a.fields !== "object" || Array.isArray(a.fields))
        return bad("fields_missing", "fields 缺失");
      if (Object.keys(a.fields).length > MAX_EXTRACT_FIELDS)
        return bad("too_many", `fields 最多 ${MAX_EXTRACT_FIELDS} 项`, "fields");
      if (!Object.values(a.fields).every((v) => typeof v === "string"))
        return bad("fields_invalid", "fields 值须为字符串");
      if (a.each !== undefined && typeof a.each !== "string")
        return bad("each_invalid", "each 须为字符串");
      if (a.when !== undefined && !(Array.isArray(a.when) && a.when.every((w) => w && typeof w === "object" && typeof w.path === "string")))
        return bad("when_invalid", "when 非法");
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
        return bad("attr_invalid", "attr 缺失");
      const err = checkEmit(a.emit, new Set(["value", "text", "page"]), rule.tier);
      if (err)
        return err;
      break;
    }
    case "manifest":
      if (a.path !== undefined && typeof a.path !== "string")
        return bad("manifest_path_invalid", "manifest.path 须为字符串");
      break;
    case "mirror":
      if (!Array.isArray(a.hosts) || a.hosts.length < 2)
        return bad("mirror_hosts_invalid", "mirror.hosts 至少两个");
      if (a.hosts.length > MAX_MIRROR_HOSTS)
        return bad("too_many", `mirror.hosts 最多 ${MAX_MIRROR_HOSTS} 个`, "mirror.hosts");
      for (const h of a.hosts) {
        if (typeof h !== "string" || !parseHostPattern(h))
          return bad("mirror_hosts_invalid", "mirror.hosts 非法");
      }
      if (scoped) {
        const scope = [...rule.match.host ?? [], ...rule.match.pageHost ?? []].flatMap((p) => parseHostPattern(p) ?? []);
        for (const h of a.hosts) {
          const domain = parseHostPattern(h)?.domain ?? "";
          if (!scope.some((p) => hostMatchesPattern(domain, p)))
            return bad("mirror_out_of_scope", `社区规则的 mirror.hosts 必须在 match.host / pageHost 范围内: ${h}`, h);
        }
      }
      break;
    case "title":
    case "player": {
      const sel = checkSelector(a.selector);
      if (sel)
        return sel;
      if (a.kind === "title" && a.attr !== undefined && typeof a.attr !== "string")
        return bad("attr_invalid", "attr 须为字符串");
      if (a.kind === "player" && a.float !== "hide")
        return bad("player_float_invalid", "player.float 非法");
      if (!hasHost(rule.match) && rule.tier !== "local")
        return bad("page_scope_required", "page 规则必须限定 host 或 pageHost");
      break;
    }
    case "headers": {
      if (rule.tier === "plugin")
        return bad("headers_plugin_forbidden", "plugin 规则不得改写请求头");
      if (!a.set || typeof a.set !== "object" || Array.isArray(a.set))
        return bad("headers_set_missing", "headers.set 缺失");
      const entries = Object.entries(a.set);
      if (entries.length === 0 || entries.length > ALLOWED_RULE_HEADERS.size)
        return bad("headers_count_invalid", "headers.set 数量非法");
      const seen = new Set;
      for (const [name, value] of entries) {
        const lower = name.toLowerCase();
        if (!/^[a-z0-9-]{1,64}$/i.test(name))
          return bad("header_name_invalid", "header 名非法", name);
        if (!ALLOWED_RULE_HEADERS.has(lower))
          return bad("header_not_allowed", `不允许设置 ${name}`, name);
        if (seen.has(lower))
          return bad("header_name_invalid", `header 名重复: ${name}`, name);
        seen.add(lower);
        if (typeof value !== "string" || value.length > 1024 || /[\r\n]/.test(value))
          return bad("header_value_invalid", "header 值非法", name);
      }
      if (!(Array.isArray(rule.match.host) && rule.match.host.length > 0))
        return bad("headers_host_required", "headers 规则必须限定 match.host");
      break;
    }
  }
  return null;
}
function validatePack(pack, expectedTier) {
  if (!pack || typeof pack !== "object")
    throw new PackRejectedError("不是对象", "pack_not_object");
  if (pack.format !== "fluxdown-sniff-pack")
    throw new PackRejectedError("format 错误", "pack_format_invalid");
  if (!(expectedTier in TIER_RANK))
    throw new PackRejectedError("expectedTier 非法", "pack_tier_invalid");
  if (pack.packId !== expectedTier)
    throw new PackRejectedError("packId 与预期层级不符", "pack_tier_mismatch");
  if (!Number.isInteger(pack.engine) || pack.engine > RULE_ENGINE_VERSION)
    throw new PackRejectedError("engine 版本过新或非法", "pack_engine_invalid");
  if (!Number.isInteger(pack.sequence) || pack.sequence < 0)
    throw new PackRejectedError("sequence 非法", "pack_sequence_invalid");
  if (!Array.isArray(pack.rules) || pack.rules.length > MAX_RULES_PER_PACK)
    throw new PackRejectedError("rules 非法或超过上限", "pack_rules_invalid");
  const seen = new Set;
  const accepted = [];
  const rejected = [];
  for (const rule of pack.rules) {
    const id = typeof rule?.id === "string" ? rule.id : "";
    if (id && seen.has(id)) {
      rejected.push({ id, code: "id_duplicate", reason: "id 重复", rule });
      continue;
    }
    const problem = checkRule(rule, expectedTier);
    if (problem) {
      rejected.push({ id, code: problem.code, ...problem.param === undefined ? {} : { param: problem.param }, reason: problem.detail, rule });
      continue;
    }
    seen.add(id);
    accepted.push(rule);
  }
  return { pack: { ...pack, rules: accepted }, rejected };
}

// fluxDown/rules/engine.ts
var BUILTIN_PACK = builtin_default;
var BUNDLED_OFFICIAL_PACK = official_default;
var TRUSTED_PACKS = new WeakSet([BUILTIN_PACK, BUNDLED_OFFICIAL_PACK]);
function rejectedEntry(raw, tier, index, problem) {
  const r = raw !== null && typeof raw === "object" && !Array.isArray(raw) ? raw : {};
  const rule = {
    ...r,
    id: typeof r.id === "string" && r.id !== "" ? r.id : `${tier}.#${index + 1}`,
    tier,
    version: Number.isInteger(r.version) ? r.version : 0,
    stage: typeof r.stage === "string" ? r.stage : "",
    title: typeof r.title === "string" ? r.title : undefined
  };
  const entry = { rule, status: "rejected", detail: problem.detail, code: problem.code };
  if (problem.param !== undefined)
    entry.param = problem.param;
  return entry;
}
function lowerUrlOf(c) {
  return c.lowerUrl ??= asciiLower(c.url);
}
function headerOf(c, name) {
  if (c.rawHeaders === undefined)
    return;
  if (c.lowerHeaders === undefined) {
    const map = new Map;
    for (const [k, v] of Object.entries(c.rawHeaders))
      map.set(k.toLowerCase(), v);
    c.lowerHeaders = map;
  }
  return c.lowerHeaders.get(name);
}
var lastPageUrl = "";
var lastPageHost = "";
function pageHostOf(pageUrl) {
  if (pageUrl === "")
    return "";
  if (pageUrl !== lastPageUrl) {
    lastPageHost = hostOf(pageUrl);
    lastPageUrl = pageUrl;
  }
  return lastPageHost;
}
function normalizeMime(mime) {
  if (mime === undefined)
    return "";
  const semi = mime.indexOf(";");
  return (semi < 0 ? mime : mime.slice(0, semi)).trim().toLowerCase();
}
function makeCtx(url, pageUrl, extra = {}) {
  const parts = parseUrlParts(url);
  return {
    url,
    host: parts.host,
    pageHost: pageUrl === url ? parts.host : pageHostOf(pageUrl),
    path: parts.path,
    ext: parts.ext,
    mime: normalizeMime(extra.mime),
    resourceType: extra.resourceType,
    status: extra.status,
    size: extra.size ?? 0,
    attachment: extra.attachment ?? false,
    rawHeaders: extra.headers,
    lowerUrl: undefined,
    lowerHeaders: undefined
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
function isCappedTier(tier) {
  return tier !== "builtin" && tier !== "official";
}
function compileRegexTest(source, capped) {
  let re;
  try {
    re = new RegExp(source, "i");
  } catch {
    return null;
  }
  return capped ? (s) => s.length <= REGEX_INPUT_CAP && re.test(s) : (s) => re.test(s);
}
function compileMatch(m, capped) {
  const preds = [];
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
  if (m.host) {
    const hs = compileHosts(m.host);
    preds.push((c) => c.host !== "" && hs.some((p) => hostMatchesLower(c.host, p)));
  }
  if (m.pageHost) {
    const hs = compileHosts(m.pageHost);
    preds.push((c) => c.pageHost !== "" && hs.some((p) => hostMatchesLower(c.pageHost, p)));
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
    const exact = new Set;
    const prefixes = [];
    for (const spec of m.mime) {
      const s = spec.toLowerCase();
      if (s.endsWith("*"))
        prefixes.push(s.slice(0, -1));
      else
        exact.add(s);
    }
    preds.push((c) => c.mime !== "" && (exact.has(c.mime) || prefixes.some((p) => c.mime.startsWith(p))));
  }
  if (m.pathRegex !== undefined) {
    const test = compileRegexTest(m.pathRegex, capped);
    preds.push((c) => test !== null && test(c.path));
  }
  if (m.url) {
    const globs = m.url.map(compileGlob);
    preds.push((c) => {
      const lower = lowerUrlOf(c);
      return globs.some((g) => g(lower));
    });
  }
  if (m.header) {
    const hs = m.header.map((h) => ({ name: h.name.toLowerCase(), test: compileRegexTest(h.regex, capped) }));
    preds.push((c) => hs.every((h) => {
      const v = headerOf(c, h.name);
      return v !== undefined && h.test !== null && h.test(v);
    }));
  }
  switch (preds.length) {
    case 0:
      return () => true;
    case 1:
      return preds[0];
    case 2: {
      const [a, b] = preds;
      return (c) => a(c) && b(c);
    }
    default:
      return (c) => preds.every((p) => p(c));
  }
}
function compileRuleMatcher(match, exclude, capped) {
  const main = compileMatch(match, capped);
  const ex = (exclude ?? []).map((e) => compileMatch(e, capped));
  if (ex.length === 0)
    return main;
  return (c) => main(c) && !ex.some((p) => p(c));
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
function buildExtIndex(rules) {
  const keys = new Set;
  for (const r of rules)
    for (const e of r.exts ?? [])
      keys.add(e);
  return { rules, keys, byExt: new Map, noExt: rules.filter((r) => r.exts === null) };
}
function candidates(index, ext) {
  if (ext === "" || !index.keys.has(ext))
    return index.noExt;
  let list = index.byExt.get(ext);
  if (list === undefined) {
    list = index.rules.filter((r) => r.exts === null || r.exts.has(ext));
    index.byExt.set(ext, list);
  }
  return list;
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
function buildClassifier(rules) {
  const index = buildExtIndex(rules);
  return (url, mime) => {
    const c = makeCtx(url, "", { mime });
    for (const r of candidates(index, c.ext)) {
      if (r.matches(c))
        return r.type;
    }
    return "other";
  };
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
      const max = e.versions === "*" ? Number.POSITIVE_INFINITY : e.versions?.max;
      if (typeof max !== "number" || !(rule.version <= max))
        continue;
      if (e.action === "hard")
        return "hard";
      found = "soft";
    }
    return found;
  };
  for (const { tier, pack: rawPack } of packs) {
    if (rawPack.engine > RULE_ENGINE_VERSION) {
      for (const rule of Array.isArray(rawPack.rules) ? rawPack.rules : []) {
        listing.push({ rule, status: "engine-too-new" });
      }
      continue;
    }
    let pack;
    if (TRUSTED_PACKS.has(rawPack) && rawPack.packId === tier) {
      pack = rawPack;
    } else {
      try {
        const validated = validatePack(rawPack, tier);
        pack = validated.pack;
        for (const r of validated.rejected) {
          listing.push(rejectedEntry(r.rule, tier, rawPack.rules.indexOf(r.rule), {
            detail: r.reason,
            code: r.code,
            param: r.param
          }));
        }
      } catch (e) {
        if (!(e instanceof PackRejectedError))
          throw e;
        if (Array.isArray(rawPack?.rules)) {
          rawPack.rules.forEach((rule, i) => listing.push(rejectedEntry(rule, tier, i, { detail: e.message, code: e.code })));
        }
        continue;
      }
    }
    let paused = null;
    if (tier === "community") {
      if (!options.communityEnabled) {
        paused = { status: "paused" };
      } else if (pack.expiresAt !== undefined && !(isoMs(pack.expiresAt) > now)) {
        paused = { status: "expired", reason: "pack-expired" };
      } else if (!revokeValid) {
        paused = { status: "expired", reason: "revocations-stale" };
      }
    }
    for (const rule of pack.rules) {
      const ov = overrides[rule.id];
      const rev = revocationOf(rule);
      if (rev === "hard") {
        listing.push({ rule, status: "hard-revoked" });
        continue;
      }
      if (paused) {
        listing.push({ rule, ...paused });
        continue;
      }
      if (rev === "soft" && !(ov?.enabled === true && ov.ackRevocation === revocations?.sequence)) {
        listing.push({ rule, status: "soft-revoked" });
        continue;
      }
      const enabled = ov ? ov.enabled : rule.enabled !== false;
      if (!enabled) {
        listing.push({ rule, status: "disabled" });
        continue;
      }
      const entry = { rule, status: "active" };
      listing.push(entry);
      active.push({ rule, order: order++, entry });
    }
  }
  active.sort((a, b) => TIER_RANK[a.rule.tier] - TIER_RANK[b.rule.tier] || (b.rule.priority ?? 0) - (a.rule.priority ?? 0) || a.order - b.order);
  const toC = (rule) => {
    const capped = isCappedTier(rule.tier);
    return {
      ref: { id: rule.id, version: rule.version, tier: rule.tier },
      rule,
      matches: compileRuleMatcher(rule.match, rule.exclude, capped),
      exts: rule.match.ext ? new Set(rule.match.ext.map((e) => e.toLowerCase())) : null,
      pageHostPred: rule.match.pageHost ? compileMatch({ pageHost: rule.match.pageHost }, capped) : null
    };
  };
  const compiled = new Map;
  active.forEach((a, i) => {
    try {
      compiled.set(a.rule, toC(a.rule));
      a.entry.evalOrder = i;
      if (a.rule.stage === "response") {
        if (a.rule.classifyOnly)
          a.entry.inert = "classify-only";
        else if (a.rule.requires === "sniffImages" && !options.sniffImages)
          a.entry.inert = "requires-setting";
      }
    } catch (e) {
      a.entry.status = "rejected";
      a.entry.detail = e instanceof Error ? e.message : String(e);
      a.entry.code = "compile_failed";
    }
  });
  const byKind = (...kinds) => active.filter((a) => kinds.includes(a.rule.action.kind)).flatMap((a) => compiled.get(a.rule) ?? []);
  const responseRules = byKind("resource", "ignore");
  const stripRules = byKind("strip-params");
  const filenameRules = byKind("filename");
  const trackRules = byKind("track");
  const bodyRules = byKind("extract", "manifest");
  const domRuleList = byKind("dom");
  const pageRules = byKind("title", "player");
  const headerRules = byKind("headers");
  const mirrorRules = byKind("mirror");
  const participates = (r) => !r.rule.classifyOnly && !(r.rule.requires === "sniffImages" && !options.sniffImages);
  const responseIndex = buildExtIndex(responseRules.filter(participates));
  const ignoreIndex = buildExtIndex(responseRules.filter((r) => r.rule.action.kind === "ignore"));
  const resourceType = (r) => r.rule.action.type;
  const classifyCRules = responseRules.filter((r) => r.rule.action.kind === "resource" && (r.rule.match.mime || r.rule.match.ext));
  const classify = buildClassifier(classifyCRules.map((r) => ({ type: resourceType(r), exts: r.exts, matches: r.matches })));
  let classifyRuleList = null;
  const known = new Set;
  for (const c of responseRules) {
    if (c.rule.action.kind !== "resource")
      continue;
    for (const e of c.rule.match.ext ?? [])
      known.add(e.toLowerCase());
  }
  const emitScope = new Map;
  for (const { rule } of active) {
    if (rule.tier === "community" || rule.tier === "plugin") {
      emitScope.set(rule.id, compileHosts([...rule.match.host ?? [], ...rule.match.pageHost ?? []]));
    }
  }
  const emitAllowed = (rule, url) => {
    const scope = emitScope.get(rule.id);
    if (scope === undefined)
      return true;
    const host = hostOf(url);
    return host !== "" && scope.some((p) => hostMatchesLower(host, p));
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
  const trackTest = new Map;
  for (const c of trackRules) {
    const a = c.rule.action;
    if (a.kind !== "track")
      continue;
    try {
      trackTest.set(c.rule.id, new RegExp(a.pattern, "i"));
    } catch {
      trackTest.set(c.rule.id, null);
    }
  }
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
    const m = /[?&]mime=([^&#]*)/i.exec(url);
    if (!m)
      return null;
    let value;
    try {
      value = decodeURIComponent(m[1]).toLowerCase();
    } catch {
      value = m[1].toLowerCase();
    }
    if (value.startsWith("audio"))
      return "audio";
    if (value.startsWith("video"))
      return "video";
    return null;
  };
  const responseCtx = (i) => makeCtx(i.url, i.pageUrl, {
    mime: i.mime,
    size: i.size,
    status: i.status,
    headers: i.headers,
    attachment: i.attachment,
    resourceType: i.resourceType
  });
  return {
    classifyResponse(i) {
      const c = responseCtx(i);
      for (const r of candidates(responseIndex, c.ext)) {
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
    explainResponse(i) {
      const c = responseCtx(i);
      const out = [];
      for (const r of candidates(responseIndex, c.ext)) {
        if (!r.matches(c))
          continue;
        const kind = r.rule.action.kind;
        if (kind !== "ignore" && kind !== "resource")
          continue;
        out.push({ ref: r.ref, decision: kind, winner: out.length === 0 });
      }
      return out;
    },
    classify,
    classifyRules() {
      classifyRuleList ??= classifyCRules.map((r) => {
        const out = { type: resourceType(r), tier: r.rule.tier, match: r.rule.match };
        if (r.rule.exclude?.length)
          out.exclude = r.rule.exclude;
        return out;
      });
      return classifyRuleList;
    },
    isIgnored(url, pageUrl, attachment) {
      const c = makeCtx(url, pageUrl, { attachment });
      for (const r of candidates(ignoreIndex, c.ext)) {
        if (r.matches(c))
          return r.ref;
      }
      return null;
    },
    dedupeKey(url, pageUrl) {
      try {
        const u = new URL(url);
        u.hash = "";
        let strip = globalStrip;
        if (scopedStrip.length > 0) {
          const c = makeCtx(url, pageUrl);
          for (const r of scopedStrip) {
            const a = r.rule.action;
            if (a.kind === "strip-params" && r.matches(c)) {
              if (strip === globalStrip)
                strip = new Set(globalStrip);
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
        if (a.kind !== "filename" || !r.matches(c))
          continue;
        const ext = extractExtension(url, a.extFromQuery, known);
        if (ext)
          return ext;
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
        const re = trackTest.get(r.rule.id);
        if (re) {
          const capped = isCappedTier(r.rule.tier);
          for (const text of [input.filename, input.url]) {
            if (!text || capped && text.length > REGEX_INPUT_CAP)
              continue;
            const g = re.exec(text)?.[a.group];
            if (g === undefined)
              continue;
            if (a.audio.includes(g))
              return "audio";
            if (!a.video || a.video.includes(g))
              return "video";
          }
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
        if (r.pageHostPred && !r.pageHostPred(c))
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
var bundledCache = new Map;
export {
  BUILTIN_PACK,
  PackRejectedError,
  RULE_ENGINE_VERSION,
  compileRules,
  hostMatchesPattern,
  parseHostPattern,
  validatePack
};
