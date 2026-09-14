# mcp-oauth-hosting

[English](README.md) · **中文**

> 本文是 [README.md](README.md) 的中文翻译。两者若有出入，**以英文版为准**（代码、注释与命令一律以仓库中的英文原文为准）。

**把你的个人或团队知识库通过 MCP 接入任意端点 —— 任何客户端，一个 HTTPS URL 即可。默认只读；也可以选择让客户端把笔记投递进某个收件目录。不需要自定义 header 字段，不用粘贴密钥，也不必注册 OAuth 服务商。**

指向一个 markdown 文件夹 —— Obsidian 库、wiki 导出、`docs/` 目录 —— 它就会把这个知识库变成一个远程 MCP 服务，暴露两个工具：`search_kb` 与 `get_doc`。知识始终留在你自己的机器或 VPS 上；客户端只靠一个 URL 就能访问。

因为它对外只暴露**一个 HTTPS URL，别无其他**，所以任何端点的**任何**客户端都能连 —— 桌面 App、手机与移动 Agent、Grok App 这类聊天助手 —— 包括那些没有「添加 header」输入框、没有 bearer key 输入位、也无法读取本地文件路径的客户端。在这些客户端里，静态的 `Authorization: Bearer` 密钥根本无处可填，它们只会报一句*「无法连接到服务器」*。

而这些客户端**真正**支持的是标准的 **OAuth 2.1 发现流程**：

```
POST /mcp                                    -> 401  WWW-Authenticate: Bearer resource_metadata="..."
GET  /.well-known/oauth-protected-resource    -> 哪个是授权服务器？
GET  /.well-known/oauth-authorization-server  -> 有哪些端点？
POST /register                                -> 动态客户端注册（RFC 7591）
GET  /authorize                               -> 打开浏览器，由人来点同意
POST /token                                   -> code + PKCE  ->  bearer token
POST /mcp   Authorization: Bearer <token>     -> tools/list、tools/call
```

所以本仓库提供一个 **约 380 行的即插即用垫片**，在你的静态密钥之上精确实现上述端点 —— 另外还包括一个用于演示的极简 markdown MCP 服务、一个 systemd 单元，以及把它通过 Cloudflare Tunnel 发布出去的脚本；并且可选地在授权页前面挂上 **Cloudflare Access**，让人用 SSO 登录来授权，而不是共享一个密钥。

对团队而言，同一层 Access 会把「同意」这一步放到 SSO 之后：每位成员用自己的身份授权，而不必传来传去共用一把钥匙。

```
        客户端（Grok / 任意 MCP 客户端）                   你的 VPS
   ┌───────────────────────────────────┐        ┌────────────────────────────┐
   │ https://mcp.example.com/mcp       │        │ 127.0.0.1:8081             │
   │  ├─ 无密钥 → 401 + resource_meta  │        │  mcp_server.py             │
   │  ├─ 发现 OAuth 元数据             │───────▶│   ├─ /health               │
   │  ├─ 自行注册                      │        │   ├─ /mcp      (bearer)    │
   │  └─ 浏览器打开 /authorize         │        │   └─ oauth_shim.py         │
   └───────────────────────────────────┘        │       /.well-known/*       │
              ▲  302 携带 ?code                  │       /register /authorize │
              │                                  │       /token    /revoke    │
    Cloudflare Tunnel（proxied CNAME）           └────────────────────────────┘
    可选：Access 应用只挂在 /authorize*  ──▶  “log in with Cloudflare” 授权页
```

## 快速开始（本地 5 分钟）

```bash
git clone https://github.com/ierhgfiuoergerg/mcp-oauth-hosting.git && cd mcp-oauth-hosting
python3 -m venv .venv && ./.venv/bin/pip install -r requirements.txt

# 然后运行它。注意：环境变量要给到「服务进程」——写成 `VAR=x cmd1 && cmd2`
# 时变量只作用于 cmd1，服务会因缺少 MCP_TOKEN 直接退出。
export MCP_TOKEN=$(openssl rand -hex 32)
export KB_DIR=./examples/kb
export MCP_PUBLIC_BASE=http://127.0.0.1:8081
export HOST=127.0.0.1 PORT=8081
./.venv/bin/python mcp_server.py
```

```bash
curl -s localhost:8081/health                         # {"ok":true,"docs":2,...}
curl -si -X POST localhost:8081/mcp | head -3         # 401 + resource_metadata
bash tests/run_all.sh                                 # 61 项断言，全部离线
```

接下来把它放到公网上（TLS 对任何真实客户端都是硬性前提）：

```bash
sudo bash deploy/install.sh                # 安装到 /opt/mcp-server + systemd（只绑 127.0.0.1）
$EDITOR /etc/mcp-server.env                # 填 MCP_PUBLIC_BASE、MCP_ALLOWED_HOSTS
cloudflared tunnel create mcp              # 也可以用 ngrok / nginx + certbot
ZONE=example.com SUB=mcp TUNNEL_ID=<uuid> bash scripts/add_cname.sh
python3 scripts/selftest_oauth.py https://mcp.example.com
```

把 `https://mcp.example.com/mcp` 粘进客户端。它会自动发现、注册、打开授权页、拿到 token，然后调用你的工具。

## 用 Cloudflare Access 实现免密钥授权（可选）

在授权页里输入一个密钥，本质上仍是「把密钥放进了浏览器」。更好的做法是把 Access 应用**只**限定在 **`/authorize*`**：

```bash
ACC=<account_id> HOST=mcp.example.com bash scripts/provision_cf_access_app.sh
# 会输出 MCP_CF_ACCESS_TEAM / MCP_CF_ACCESS_AUD → 写进 /etc/mcp-server.env 后重启
```

这样 `/authorize` 就处在 Cloudflare 自己的 SSO 之后（身份在服务端用 `Cf-Access-Jwt-Assertion` 的 RS256 签名校验），授权页会显示「已通过 Cloudflare Access 认证：you@example.com → **授权**」，完全没有密钥输入框。其余一切 —— `/mcp`、`/token`、`/.well-known/*` —— 刻意**不**放在 Access 之后：非浏览器客户端无法完成交互式登录页，把它们包进去恰恰会弄断连接。

配置脚本会专门探测这个错误，一旦 `/mcp` 不再返回你自己的 401，它会自动回滚。

## 可选：让客户端写入 —— 只能写进一个目录

设置 `KB_WRITE_MODE=inbox` 后，服务会额外暴露 `submit_doc(title, content, tags, filename)`。适用于「手机上的 Agent 应该能把一条笔记丢进我的知识库，但我并不想要一个 LLM 可写的文件系统」这种场景。

三道彼此独立的防线，任意一道单独就能挡住目录穿越：

1. **接口里根本没有目录参数。** 工具签名中不存在任何路径参数，落盘位置由服务端常量决定（`KB_DIR` + `KB_INBOX_DIR`）。客户端无从把它指向别处。
2. **文件名经过清洗。** `/` 与 `\` 变 `-`；控制字符与类 shell 字符被折叠；`..`、首尾点和长度都被处理；空输入变成 `untitled`。对**任意**输入都成立的不变量：不含 `/`、不含 `\`、不含 `..`、不为 `.`/`..`、非空、长度 ≤ 80。
3. **落盘前断言解析后的路径**确实就位于收件目录内（`target.parent != INBOX_DIR` ⇒ 拒绝）。

另外：已存在的文件**永不覆盖** —— 同名冲突会追加时间戳，原文件保留。写入会使索引缓存失效，所以投递的内容立刻可以搜到。

```bash
KB_WRITE_MODE=inbox KB_INBOX_DIR=inbox ./... mcp_server.py
```

客户端传什么 vs 实际落在哪里（来自 `scripts/selftest_inbox.py`）：

| 客户端传入的 `filename` | 实际写入的文件 |
| --- | --- |
| `../../../../tmp/pwned` | `inbox/tmp-pwned.md` |
| `/etc/cron.d/pwned` | `inbox/etc-cron.d-pwned.md` |
| `..%2f..%2fescape` | `inbox/2f..2fescape.md` |
| `....//....//deep-escape` | `inbox/deep-escape.md` |

**frontmatter 可配置**，因为投递进来的笔记最终要落进**你的**知识库，而各家知识库对元数据的约定并不一致。默认值是通用的（`source: mcp`，不写 `type`）；按你自己的 lint 规则去映射即可：

```bash
KB_INBOX_TYPE=inbox KB_INBOX_SOURCE=ai KB_INBOX_STATUS=raw   # 例如某个 wiki 要求这几个取值
```

默认是 `off` —— 一个不会写入的服务，也就无法被说服去写入。

## 仓库内容

| 文件 | 说明 |
| --- | --- |
| `oauth_shim.py` | OAuth 2.1 垫片：发现、DCR、授权页、PKCE 换取 token、刷新、撤销。可选的 Cloudflare Access 身份校验。 |
| `mcp_server.py` | 极简 Streamable-HTTP MCP 服务：在一个 `.md` 文件夹之上提供 `search_kb` + `get_doc` —— 带索引缓存、凭据类文件排除 —— bearer 鉴权（header / query / path / share-slug）、Host 白名单、`/health`。设置 `KB_WRITE_MODE=inbox` 后，另有 `submit_doc`，且仅限一个目录。 |
| `deploy/install.sh` + `deploy/mcp-server.service` | 加固的 systemd 安装（DynamicUser、`ProtectSystem=strict`、只绑 127.0.0.1）。 |
| `scripts/provision_cf_access_app.sh` | 通过 API 创建限定路径的 Access 应用 + 安全探测 + 回滚。 |
| `scripts/add_cname.sh` | proxied CNAME → `<tunnel-id>.cfargotunnel.com`，幂等。 |
| `scripts/selftest_oauth.py` | 完整走一遍 URL-only 客户端要走的路；14 项断言。 |
| `scripts/selftest_cf_jwt.py` | 用本地自签 JWT 证明签名校验有效（9 项断言，不需要 Cloudflare）。 |
| `scripts/selftest_inbox.py` | 自包含（自建临时知识库、在空闲端口起服务、结束后清理）：20 项断言，覆盖写入限域、四种穿越形状的文件名、兄弟目录前缀陷阱、凭据排除、缓存失效。 |
| `scripts/test_safe_stem.py` | 文件名清洗函数的单元测试，通过 AST 从真实源码中提取 —— 18 个用例 + 一条对任意输入都必须成立的不变量。 |
| `tests/run_all.sh` | 以上全部，离线，一条命令。 |
| `references/` | 规范、坑位与安全推理。 |
| `SKILL.md` | 同一套流程打包成的 agent skill。 |

## 环境变量

带注释的完整列表见 `env.example`。重点如下：

| 变量 | 含义 |
| --- | --- |
| `MCP_TOKEN` | 访问密钥（64 位十六进制）。必填。 |
| `MCP_PUBLIC_BASE` | 公开 https 源；启用 OAuth 垫片。 |
| `KB_DIR` | 要暴露的 markdown 文件夹。 |
| `MCP_ALLOWED_HOSTS` | Host 白名单（`mcp.example.com`、`*.example.com`）。 |
| `MCP_SHARE_SLUG` | 用于 `/s/<slug>/mcp` 密钥内嵌访问的**独立**一次性钥匙。 |
| `MCP_OAUTH_STATE` | 客户端与 refresh token 的存储位置（chmod 600）。 |
| `MCP_CF_ACCESS_TEAM` / `MCP_CF_ACCESS_AUD` | 启用免密钥的 Cloudflare Access 授权页。 |
| `KB_WRITE_MODE` | `off`（默认 —— 严格只读）或 `inbox`（暴露 `submit_doc`）。 |
| `KB_INBOX_DIR` | `submit_doc` 唯一可写入的目录（默认 `inbox`）。 |
| `KB_EXCLUDE_DIRS` / `KB_EXCLUDE_GLOBS` | 把凭据类文档挡在索引之外，即使它们就在 `KB_DIR` 里。 |
| `KB_MAX_DOC_BYTES` / `KB_MAX_WRITE_BYTES` / `KB_CACHE_TTL` | 单篇索引上限（2 MiB）、单篇写入上限（512 KiB）、缓存寿命（3 秒）。 |
| `KB_INBOX_SOURCE` / `KB_INBOX_TYPE` / `KB_INBOX_STATUS` | 写入投递内容的 frontmatter（默认 `mcp` / 不写 / `raw`）—— 设成与你知识库 schema 一致的值。 |

## 会踩的坑

* **包含性检查要用 `Path.is_relative_to()`，绝不要用 `str.startswith()`。** `"/kb-evil/x.md".startswith("/kb")` 为 `True` —— 一个仅仅名字前缀相同的兄弟目录会被放行读取。`scripts/selftest_inbox.py` 专门断言了这个用例。
* **Access 要包 `/authorize`，绝不要包 `/mcp`。** 非浏览器客户端撞上 Cloudflare 登录页会直接失败。
* **隧道上的 `HTTP 421 "Misdirected Request"`**：源站收到的 `Host`/`:authority` 不对（h2 → HTTP/1.1 重写）。去修隧道的 `originRequest`（`http2Origin`、`originServerName`）—— 不要靠关掉 TLS 校验来「修」它。
* **Python 默认 UA 会被拦截**：某些 zone 上 Cloudflare 会挡；测试时始终用浏览器 UA。
* **跟随重定向要设为 0**（否则会丢掉 302 与 `Location`）；响应头的 key 是小写的。
* **只返回 JSON** 能让客户端更省心：`POST /mcp` 返回 `application/json`，而不是开一条永不结束的 SSE 流。
* **带 IP 白名单的 token + IPv6 出口** = Cloudflare 错误 `9109`。API 调用强制走 IPv4。
* **泄露后要轮换**：只要密钥曾经过 URL、工单或聊天记录，就当作已烧毁 —— 改 env 文件、重启，客户端重新授权一次即可。

## 这个项目不是什么

它不是身份提供方。客户端拿到的 token **就是**你的静态密钥，因此没有按用户区分的授权、没有超出你自己实现范围的 scope 管控，也没有超出你日志范围的审计轨迹。如果你需要真正的多用户访问控制，请在它前面放一个真正的 IdP（或者把 Cloudflare Access 配合 service token 挂到每一条路径上）。参见 `references/security.md`。

MIT 许可。
