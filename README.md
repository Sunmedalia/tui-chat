<div align="center">

# tui-chat

**一个面向终端的 Rust 端到端加密聊天工具**

家庭电脑、NAS 和 NAT 后的服务器主动连接公网中继，无需开放入站端口。

[![CI](https://github.com/Sunmedalia/tui-chat/actions/workflows/ci.yml/badge.svg)](https://github.com/Sunmedalia/tui-chat/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/Sunmedalia/tui-chat)](https://github.com/Sunmedalia/tui-chat/releases/latest)
[![Rust 1.95](https://img.shields.io/badge/Rust-1.95-dea584?logo=rust)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#许可证)

[快速开始](#本地快速开始) · [操作指南](#tui-操作) · [公网部署](#docker-公网部署) · [服务端管理](#服务端管理) · [下载 Release](https://github.com/Sunmedalia/tui-chat/releases/latest)

</div>

消息使用 Olm 双棘轮按设备端到端加密。服务端负责账号管理、在线连接、离线密文保存和消息转发，但无法读取消息正文。

> [!WARNING]
> 当前项目是可运行的安全 MVP，尚未经过独立安全审计。不要将它视为 Signal 等成熟产品的等价替代品。

> [!IMPORTANT]
> 当前网络协议为 **v2**，新连接应使用 `/v2/ws`。0.2.x 客户端会把命令行中的旧 `/v1/ws` 兼容改写为 `/v2/ws`，但 v1 客户端无法连接 v2 服务端。

## 文档导航

| 我想要…… | 前往 |
|---|---|
| 在本机启动服务端并让两个账号聊天 | [本地快速开始](#本地快速开始) |
| 熟悉键盘、鼠标、Emoji 和通知操作 | [TUI 操作](#tui-操作) |
| 为同一账号批准另一台电脑 | [添加第二台设备](#添加第二台设备) |
| 使用域名、Docker 和自动 TLS 对外部署 | [Docker 公网部署](#docker-公网部署) |
| 创建用户、吊销设备、备份或清理数据 | [服务端管理](#服务端管理) |
| 理解数据保存、升级与恢复方式 | [数据、备份与迁移](#数据备份与迁移) |
| 排查口令、连接或终端操作问题 | [常见问题](#常见问题) |

## 功能概览

| 领域 | 能力 |
|---|---|
| 聊天 | 一对一文字聊天、离线消息、密文历史自动补拉 |
| 状态 | 发送中、已发送、已送达、已读；只有接收端窗口聚焦时才发送已读回执 |
| 端到端加密 | 每台设备拥有独立身份密钥和 Olm 预密钥，消息按设备加密 |
| 多设备 | 已有设备通过 SAS 短认证码批准新设备；成功后自动热切换，且会话请求、处理结果和删除状态跨设备同步 |
| 本地保护 | 消息、草稿、Olm 状态和私钥由随机 VaultKey 加密，Argon2id 用于解锁 |
| 网络安全 | 强制公网使用 WSS、系统 CA 校验、可选 SPKI 公钥固定 |
| 稳定性 | 持久化 outbox、同步游标、离线补拉、心跳和指数退避重连 |
| TUI | Unicode/Emoji、可持久化主题、可收起侧边栏、命令补全、鼠标操作、加密草稿、分页历史和响应式布局 |
| 管理 | 账号仅由管理员创建；支持用户、设备、在线会话、密文和备份管理 |

## 架构

```text
家庭电脑 / NAT 客户端 ─┐
                       ├── WSS ── 公网服务器 ── SQLite 密文存储
NAS / 远程客户端 ──────┘

Alice 设备 ═════════════ Olm 端到端密文 ═════════════ Bob 设备
                         服务端不能解密
```

服务端仍然可以观察用户名、IP 地址、通信双方、时间和密文大小，也可以拒绝或延迟消息。匿名通信、流量分析防护和已被攻陷的终端不在当前威胁模型内。

## 下载与构建

### 下载客户端

[最新 Release](https://github.com/Sunmedalia/tui-chat/releases/latest) 提供以下预编译客户端，每个压缩包旁都有对应的 SHA-256 校验文件：

| 平台 | Rust target | Release 文件 |
|---|---|---|
| Linux x86_64 | `x86_64-unknown-linux-gnu` | `tui-chat-linux-x86_64.tar.gz` |
| macOS Intel | `x86_64-apple-darwin` | `tui-chat-macos-x86_64.tar.gz` |
| macOS Apple Silicon | `aarch64-apple-darwin` | `tui-chat-macos-aarch64.tar.gz` |
| Windows x86_64 | `x86_64-pc-windows-msvc` | `tui-chat-windows-x86_64.zip` |

### 从源码构建

需要 Rust 1.95；仓库包含固定工具链和 vendored `protoc`。公网部署还需要 Docker 与 Docker Compose。推荐使用支持 UTF-8、真彩色和鼠标事件的现代终端。

构建服务端和客户端：

```console
cargo build --release --locked -p tui-chat-server -p tui-chat
```

生成的程序位于：

```text
target/release/tui-chat-server
target/release/tui-chat
```

本地客户端和普通 `cargo` 命令默认使用 crates.io。只有服务端 Docker 构建会加载 `docker/cargo-rsproxy.toml`，通过 rsproxy 下载 Rust 依赖；两者不会互相影响。

## 本地快速开始

以下流程通常可在几分钟内完成。需要同时打开三个终端：一个运行服务端，两个分别运行 Alice 和 Bob。请保持服务端终端持续运行。

### 1. 启动服务端

第一个终端：

```console
cargo run --locked -p tui-chat-server -- serve
```

默认配置为：

- 监听地址：`127.0.0.1:8080`
- 数据库：`data/server.db`
- 公共域：`localhost`

启动后看到以下日志即表示监听成功：

```text
server listening; expose it only through a TLS reverse proxy
```

也可以复制示例配置后启动：

```console
cp server.example.toml server.toml
cargo run --locked -p tui-chat-server -- --config server.toml serve
```

### 2. 创建账号

第二个终端：

```console
cargo run --locked -p tui-chat-server -- user add alice --generate-password
cargo run --locked -p tui-chat-server -- user add bob --generate-password
```

命令会打印一次性账号密码，请分别安全保存。第一次登录时，客户端会要求把一次性密码修改为新的长期账号密码。

### 3. 启动两个客户端

Alice：

```console
cargo run --locked -p tui-chat -- \
  --server ws://127.0.0.1:8080/v2/ws \
  --username alice \
  --data-dir ./data/alice-client
```

Bob：

```console
cargo run --locked -p tui-chat -- \
  --server ws://127.0.0.1:8080/v2/ws \
  --username bob \
  --data-dir ./data/bob-client
```

> [!CAUTION]
> 不要让两个账号或两台设备共用同一个 `--data-dir`。本地档案会绑定创建它的服务器、账号和设备身份。

> [!TIP]
> `--data-dir` 后面只能跟一个完整目录参数。应写成 `--data-dir ./data/alice-client`，不要写成 `--data-dir ./data/ alice-client`。

### 4. 理解登录提示

首次运行会依次出现以下提示：

| 提示 | 应输入的内容 |
|:---|:---|
| `Create local storage passphrase` | 自己创建的本地数据加密口令，至少 12 个字符 |
| `Repeat local storage passphrase` | 再输入一次本地口令 |
| `Account password` | 服务端管理员创建账号时给出的一次性密码 |
| `New account password` | 自己设置的新服务器账号密码，至少 12 个字符 |
| `Repeat new account password` | 再输入一次新账号密码 |

以后启动通常只需输入 `Local storage passphrase`。设备身份验证使用本地私钥，不会重复要求账号密码。

输入密码或本地口令时，终端不会显示字符或星号，这是正常行为。

| 凭据 | 用途 | 能否由服务端恢复 |
|---|---|---|
| 本地存储口令 | 解锁当前设备上的加密数据库 | 不能 |
| 账号密码 | 首次登录、添加待批准设备、密码重置 | 管理员可以重置 |

首次运行时，即使后续账号密码输入错误，本地 Vault 也可能已经创建。再次启动时应输入刚才创建的本地口令，不要输入账号密码。

### 5. 建立会话并核验安全码

Alice 在输入框执行：

```text
/chat bob
```

Bob 会在通知 Tab 看到 Alice 的会话请求，按 `Enter` 或点击“接受”。双方会看到一组安全码。通过电话、当面或其他可信渠道比较，确认完全一致后，点击“已核对，认证”；也可以执行：

```text
/verify
```

联系人前面从 `?` 变成 `✓` 后即可发送消息。

> [!WARNING]
> 不要在未经比较的情况下直接核验安全码，否则无法排除服务端替换身份密钥的攻击。

### 6. 退出客户端

可以在输入框执行 `/exit`、`/quit`，或直接按 `Ctrl-C` / `Ctrl-Q`。客户端会先完成当前本地原子保存，再恢复终端状态退出。

## 客户端参数

```console
tui-chat --help
```

常用参数：

| 参数 | 说明 |
|---|---|
| `--server <URL>` | 服务端 WebSocket 地址 |
| `--username <名称>` | 精确账号名 |
| `--data-dir <目录>` | 当前设备的本地数据库目录 |
| `--spki-pin <SHA256>` | 服务端证书 SPKI SHA-256，64 位十六进制 |
| `--no-mouse` | 不捕获鼠标，方便使用终端原生文本选择 |

客户端只允许对 `127.0.0.1` 和 `localhost` 使用明文 `ws://`。其他地址必须使用 `wss://`，没有跳过证书校验的开关。

如果不指定 `--data-dir`，客户端使用操作系统的应用数据目录。

## TUI 操作

### 快捷键

导航与视图：

| 快捷键 | 操作 |
|---|---|
| `Tab` / `Shift-Tab` | 在会话、消息和输入框间移动焦点；候选框打开时切换补全项 |
| `Alt-↑` / `Alt-↓` | 快速切换会话 |
| `Alt-N` / `Alt-C` | 切换通知 / 会话 Tab |
| `↑` / `↓` | 根据当前焦点选择会话、滚动消息或移动编辑光标 |
| `PageUp` / `PageDown` | 按页滚动消息 |
| `Ctrl-Home` / `Ctrl-End` | 跳到当前历史顶部或底部 |
| `Ctrl-F` | 搜索当前已加载的会话消息 |
| `F1` | 打开或关闭帮助 |
| `Esc` | 关闭补全或帮助，并返回输入区域 |

输入与编辑：

| 快捷键 | 操作 |
|---|---|
| `Enter` | 发送消息或执行命令 |
| `Shift-Enter` / `Alt-Enter` | 插入换行；无法识别 Shift-Enter 时使用 Alt-Enter |
| `Alt-E` | 打开 Unicode Emoji 选择器；输入关键词搜索，用方向键选择，Enter 插入 |
| `Ctrl-A` / `Ctrl-E` | 移到输入内容开头或结尾 |
| `Ctrl-W` / `Alt-Backspace` | 向前删除一个词 |
| `Ctrl-U` / `Ctrl-D` | 删除到行首 / 删除后一个字符 |
| `Ctrl-K` | 打开命令面板，`Tab` 选择 |

操作与退出：

| 快捷键 | 操作 |
|---|---|
| `x` | 焦点位于会话或通知列表时，打开所选项目的删除确认框 |
| `Ctrl-R` / `Ctrl-L` | 立即同步或重连 / 强制重绘屏幕 |
| `Ctrl-C` / `Ctrl-Q` | 保存草稿、恢复终端并退出 |

侧栏顶部有“会话”和“通知”两个 Tab，可直接点击切换。通知 Tab 会集中显示多设备配对、会话请求和处理结果，并始终按创建时间从新到旧排列，选中或标记已读不会改变顺序。通知详情提供可点击的“接受”“拒绝”“已核对，认证”“开始配对”和“短码一致，确认”操作，也保留 `Enter`、`r`、`d` 键盘操作。联系人认证前必须通过电话、当面等可信渠道比较安全码；设备配对也必须比较 SAS 短认证码，点击操作不会跳过这些安全确认。

底部输入框标题会显示当前账号名，例如 `输入 · @alice · Enter 发送`；用户名不会写入实际消息内容。

执行 `/theme terminal` 可切换到终端会话风格：消息使用 `alice@local:~$` / `bob@remote:~$` 提示符，输入框显示当前账号的 shell 风格标题，并使用协调的终端色板。执行 `/theme default` 恢复默认界面；选择会保存在当前客户端数据目录中，下次启动自动加载。直接执行 `/theme` 可查看当前主题和可选名称。

消息正文使用 UTF-8，可以直接输入或粘贴 Unicode Emoji。输入框边框的 `Enter 发送` 提示旁有可点击的“😊 表情”入口，也可以按 `Alt-E` 或执行 `/emoji [关键词]` 打开内置选择器。选择器会根据终端宽度把表情排成多列，可用中文/英文搜索、方向键移动，并用 `Enter` 或鼠标点击插入。

部分终端无法区分 `Enter` 与 `Shift-Enter`。这种情况下可以直接粘贴多行文本，客户端已启用 bracketed paste。

### 鼠标

- 点击会话以打开聊天。
- 点击侧边栏右上角的 `[◀]` 收起会话列表；收起后点击聊天区右上角的 `[▶]` 重新展开。
- 点击会话或通知行右侧的 `x` 打开删除确认框；`x` 使用终端默认配色。确认框默认选中“取消”，可用方向键切换后按 `Enter`，也可直接点击按钮。
- 点击侧栏顶部的“会话”或“通知”切换 Tab；通知详情中的“接受”“拒绝”“已核对，认证”“开始配对”“短码一致，确认”按钮可直接执行对应操作。
- 点击输入框标题行的“😊 表情”打开选择器，再点击任意表情插入；点击弹窗外部关闭。
- 点击输入框以移动光标。
- 在会话区或消息区滚动滚轮，只滚动对应区域。
- 拖动右侧滚动条快速移动。
- 如果需要终端原生选择和复制，启动时增加 `--no-mouse`；部分终端也支持按住 `Shift` 临时绕过鼠标捕获。

### 响应式布局

终端宽度低于 72 列时，主区域切换为单栏。使用 `Tab` 在会话列表和消息区域之间切换。

执行 `/sidebar` 可以随时切换侧边栏；`/sidebar hide` 和 `/sidebar show` 可明确收起或展开。设置保存在当前客户端数据目录中。收起后消息或通知详情会使用全部主区域宽度；在窄终端重新展开时会直接返回侧边栏。

客户端初次只解密最近 100 条消息。滚动到顶部时继续分页加载；浏览旧消息时收到新消息不会强制跳到底部。

删除会话会清理当前设备上的聊天记录、草稿、联系人入口、相关会话通知和对应待发消息，并通过端到端加密控制事件同步到同账号的其他已激活设备；离线设备会在下次连接时处理。它不会撤回已经发送的消息，也不会删除对方设备上的记录或服务端仍在保留期内的端到端密文。

删除后，如果对方再次发消息或发起 `/chat`，客户端会先隔离正文，并在通知 Tab 生成新的认证请求。接受请求、通过可信渠道比较安全码并认证后，消息才会显示。连续收到多条待认证消息只生成一条会话通知。

删除通知也只影响当前设备，既不等于拒绝会话请求，也不会取消正在进行的设备配对；后续再次收到对应事件时仍可重新生成通知。

已读回执只在接收端的终端 pane 获得焦点、且当前选中对应会话时发送。发件端在服务端持久化后只显示“已发送”，不会立即显示“已读”。

## 聊天命令

| 命令 | 说明 |
|---|---|
| `/chat <精确用户名>` | 查询用户并发送端到端加密会话请求 |
| `/emoji [关键词]` | 打开 Unicode Emoji 选择器并可选地预填搜索词 |
| `/theme [名称]` | 查看当前主题，或切换到 `default` / `terminal` 并保存到本机 |
| `/sidebar [hide\|show\|toggle]` | 切换、收起或展开会话侧边栏，并保存到本机 |
| `/search <关键词>` | 在当前已分页加载的消息中搜索 |
| `/verify` | 核验当前联系人的安全码 |
| `/pair [设备ID]` | 已有设备开始批准新设备 |
| `/confirm` | 确认当前设备配对的 SAS 短认证码 |
| `/sync` | 继续补拉服务端历史 |
| `/help` | 打开快捷键帮助 |
| `/exit` / `/quit` | 安全退出 |
| `//文本` | 发送以 `/` 开头的普通消息 |

输入 `/` 后可以使用 `Tab` 补全命令。`/chat` 会补全已有联系人，`/pair` 会补全待处理设备，`/theme` 会补全主题名称，`/sidebar` 会补全侧边栏操作。

执行 `/chat 用户名` 后，接收方会在通知 Tab 看到会话请求。按 `Enter` 或点击“接受”后仍停留在通知页，双方都能在通知详情看到安全码。通过电话、当面等可信渠道确认完全一致后，点击“已核对，认证”或按 `Enter` 完成认证；也可以继续使用 `/verify`。在联系人显示 `✓` 前不会发送聊天正文。接收方离线时请求会由服务端暂存，重新连接后仍会出现。发起请求和接受/拒绝结果会端到端同步到同账号的其他已激活设备，任何一台设备处理后，其他设备上的通知状态也会更新。

## 添加第二台设备

同一账号在新电脑上第一次启动时：

1. 新设备使用账号密码登录。
2. 新设备保持客户端在线，等待已有设备收到加入请求。
3. 已有设备打开通知 Tab，选择配对通知并点击“开始配对”；也可以执行 `/pair [设备ID]`。
4. 新、旧设备的通知详情都会显示同一组 SAS 短认证码。
5. 通过独立可信渠道确认短码完全一致后，两边分别点击“短码一致，确认”；`/confirm` 是键盘命令备用方式。
6. 已有设备批准新设备，并通过认证通道迁移账号主密钥、联系人信任和可用历史。
7. 新设备自动使用设备签名重建正式连接并补拉离线数据，整个过程无需退出或重启客户端。

> [!IMPORTANT]
> 不要只根据服务端或同一个聊天窗口传来的数字确认配对码，应通过电话、当面等独立可信渠道比较。

如果旧设备在配对中途重启，可在原配对通知中点击“重新开始配对”。新设备会收到更新后的短码通知，双方必须重新比较和确认。

## Docker 公网部署

### 前置条件

- 一个指向服务器公网 IP 的域名。
- 防火墙开放 TCP 80 和 443。
- Docker Compose 可用。
- 不要把 Rust 服务的 8080 端口直接暴露到公网。

设置域名并启动：

```console
export CHAT_DOMAIN=chat.example.com
docker compose up -d --build
docker compose ps
```

如果当前环境没有 `docker compose` 子命令，可将上述命令中的 `docker compose` 替换为 `docker-compose`。

Compose 中：

- Caddy 对公网监听 80/443，自动申请和续签 TLS 证书。
- Rust 服务只位于内部 Docker 网络。
- 服务端数据库保存在 `chat-data` volume。
- Caddy 数据保存在 `caddy-data` 和 `caddy-config` volume。
- 对公网只接受 `/v2/ws`；`/healthz` 仅在容器内部用于健康检查。
- Rust 进程校验 Caddy 转发的 TLS 标记，并且容器使用只读根文件系统、无 Linux capabilities、进程/内存上限和日志轮转。

创建账号：

```console
docker compose exec server tui-chat-server user add alice --generate-password
docker compose exec server tui-chat-server user add bob --generate-password
docker compose exec server tui-chat-server user list
```

客户端连接：

```console
tui-chat --server wss://chat.example.com/v2/ws --username alice
```

查看日志和健康状态：

```console
docker compose logs -f server caddy
docker compose exec server tui-chat-server healthcheck
```

## SPKI 公钥固定

系统 CA 校验已经可以防御普通中间人攻击。如果还希望固定服务端证书公钥，应通过可信路径获得当前 SPKI SHA-256：

```console
openssl s_client -connect chat.example.com:443 -servername chat.example.com </dev/null 2>/dev/null \
  | openssl x509 -pubkey -noout \
  | openssl pkey -pubin -outform DER \
  | openssl dgst -sha256 -binary \
  | xxd -p -c 64
```

连接时提供固定值：

```console
tui-chat \
  --server wss://chat.example.com/v2/ws \
  --username alice \
  --spki-pin 64位十六进制摘要
```

固定值会保存在加密本地档案中。更换证书私钥前必须先安全分发新固定值；如果续签证书时继续使用原私钥，固定值不变。

## 服务端管理

本地运行时去掉下面命令中的 `docker compose exec server` 前缀即可。

```console
# 列出账号
docker compose exec server tui-chat-server user list

# 禁用或重新启用账号
docker compose exec server tui-chat-server user disable alice
docker compose exec server tui-chat-server user enable alice

# 生成新的账号密码
docker compose exec server tui-chat-server user reset-password alice --generate-password

# 列出和吊销设备
docker compose exec server tui-chat-server device list alice
docker compose exec server tui-chat-server device revoke alice DEVICE_ID

# 重置整个设备身份代次
docker compose exec server tui-chat-server user reset-devices alice

# 查看或踢下线实时连接
docker compose exec server tui-chat-server session list
docker compose exec server tui-chat-server session kick SESSION_UUID

# 查看服务端可见的会话密文统计
docker compose exec server tui-chat-server conversation list

# 先预览，确认后才清理已送达密文
docker compose exec server tui-chat-server conversation prune CONVERSATION_ID --delivered-only
docker compose exec server tui-chat-server conversation prune CONVERSATION_ID --delivered-only --yes

# 查看最近审计记录，或启动本地管理 TUI
docker compose exec server tui-chat-server audit list --limit 200
docker compose exec -it server tui-chat-server admin

# 在线备份服务端数据库
docker compose exec server tui-chat-server db backup /data/backup.db
docker compose exec server tui-chat-server db check
docker compose exec server tui-chat-server db checkpoint
```

管理 TUI/CLI 只通过 `/data/admin.sock` Unix socket 获取在线状态，不存在公网管理 HTTP API。默认保留 90 天审计事件；服务端密文不自动过期，只能由管理员显式预览后清理。

`session list`、`conversation list` 和 `admin` 需要正在运行的服务端及其 Unix socket。纯数据库命令，例如 `user list`、`db check` 和 `db backup`，可直接读取配置的 SQLite 数据库。

彻底删除账号会同时清理其设备、预密钥、会话密文、投递状态和配对事件。为防止误删，命令需要一份已存在的备份、`--yes` 以及交互输入用户名；省略 `--yes` 时只显示影响预览：

```console
docker compose exec server tui-chat-server db backup /data/before-delete.db
docker compose exec server tui-chat-server user delete alice \
  --backup /data/before-delete.db
docker compose exec -it server tui-chat-server user delete alice \
  --backup /data/before-delete.db --yes
```

原有的 `user purge` 保留为兼容别名。

`reset-devices` 会开启新的账号身份代次。旧设备密钥和旧密文可能永久不可恢复，联系人也会把主密钥变化视为高危事件并停止发送。只有明确接受这一后果时才能使用。

## 数据、备份与迁移

### 服务端

- SQLite 使用 WAL。
- 服务端先提交密文，再返回发送成功。
- 逻辑消息和逐设备信封使用稳定 UUID，重复投递不会重复入库。
- 使用 `tui-chat-server db backup` 创建一致性备份，不要只复制正在写入的主数据库文件。

### 客户端

- `client.db` 包含加密消息、草稿、私钥、Olm 状态、联系人和同步游标。
- 发送时在同一事务中保存推进后的棘轮状态、固定密文和 outbox。
- 接收时原子保存棘轮状态、加密正文和同步游标。
- 可以在客户端完全退出后备份整个 `--data-dir`。
- 恢复客户端备份必须拥有对应本地口令。

旧版客户端数据库首次升级时会生成：

```text
client.db.pre-v2-时间.bak
```

客户端随后将档案切换到 VaultKey v2，并在后台逐条迁移旧消息。迁移是幂等的，中断后下次启动可以继续。

当前网络协议版本为 v2，服务端数据库会自动迁移，但 v1 客户端不能继续连接新服务端。升级时先备份服务端和客户端数据，然后同时更新两端。客户端会将本地档案中的旧 `/v1/ws` 地址规范化为 `/v2/ws`，但命令行应尽快改用新路径。

服务端数据库不能代替客户端备份。所有设备和本地加密状态都丢失后，服务端无法恢复消息正文。

## 常见问题

### `Create local storage passphrase` 应该输入什么？

输入你自己创建的本地加密口令，至少 12 个字符。它不是服务端生成的一次性账号密码。请使用密码管理器保存。

### 为什么第二次启动只询问 `Local storage passphrase`？

这表示该 `--data-dir` 中的本地 Vault 已经创建。请输入首次运行时自己设置的本地口令。它与管理员生成的账号密码不同。

### `wrong local passphrase or corrupted vault key`

通常表示本地口令输入错误，或 `client.db` 与其原来的本地口令不匹配。不要直接删除数据库；先检查是否使用了正确的 `--data-dir`、键盘布局和本地口令。

### `unexpected argument` 是什么意思？

表示命令行中出现了不属于任何选项的额外文本。最常见原因是将数据目录错写为两段：

```console
# 错误
--data-dir ./data/ alice-client

# 正确
--data-dir ./data/alice-client
```

### 输入密码时没有任何显示

这是预期行为。终端密码输入不会回显字符或星号，输入完成后直接按 `Enter`。

### `local encrypted profile belongs to a different username or server`

当前 `--data-dir` 已经绑定另一个账号或服务器。为新账号指定一个新的空目录，不要删除仍需保留的客户端数据库。

### 使用 `/v1/ws` 会怎样？

当前客户端会将 URL 路径中的 `/v1/ws` 自动改成 `/v2/ws`，所以旧启动命令仍可以运行。这不代表 v1 协议仍被支持；新文档和脚本应直接使用 `/v2/ws`。

### 收到消息或已读回执后 TUI 退出

请同时更新并重启通信双方的客户端。新版已修复旧已读回执中的毫秒时间戳竞争，也会兼容处理服务端上已积压的问题回执。单条服务端事件失败只会显示在状态栏，不再导致整个 TUI 退出。

### 无法连接 `ws://` 公网地址

客户端有意拒绝非本机明文 WebSocket。公网部署必须使用有效证书和 `wss://`。

### `SPKI pin differs from the encrypted local profile`

当前固定值与首次保存的不一致。先通过可信渠道确认服务器是否更换证书私钥；不要为了绕过错误而删除本地数据。

### 忘记本地口令

没有恢复或重置入口。创建新的客户端数据目录会生成新设备，但旧本地消息和私钥无法解密；已有账号的第二设备仍需通过已有设备批准。

### 新设备一直显示等待批准

保持新设备在线，在已有设备的通知 Tab 点击“开始配对”，比较两边通知详情中的短认证码，然后双方点击“短码一致，确认”。也可以使用 `/pair [设备ID]` 和 `/confirm` 完成同样操作。

配对完成后客户端会自动切换到正式连接。如果网络此时不可用，状态栏会显示重试信息，并继续指数退避重连；不需要重启客户端或再次输入账号密码。

### 鼠标无法选择终端文字

使用 `--no-mouse` 启动，或者尝试按住终端支持的鼠标绕过修饰键，通常是 `Shift`。

### `Shift-Enter` 没有插入换行

部分终端不会报告 Enter 的 Shift 修饰键。可以粘贴多行文本，或改用支持增强键盘协议的终端。

## 开发与质量检查

```console
cargo fmt --all -- --check
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo build --release --locked -p tui-chat-server -p tui-chat
```

CI 还会执行依赖许可证、来源和安全公告策略检查，并为 Linux、macOS 和 Windows 构建客户端产物。

## 发布客户端

推送版本标签后，GitHub Actions 会构建并发布 Linux x86_64、macOS Intel、macOS Apple Silicon 和 Windows x86_64 客户端压缩包，同时生成 SHA-256 校验文件。Intel 构建使用 `macos-15-intel` runner：

```console
git tag v0.2.1
git push origin v0.2.1
```

## 当前限制

- 只支持一对一文字聊天。
- 不支持群聊、附件、编辑、撤回、回复、表情反应和输入状态。
- 不提供公开用户搜索或客户端注册。
- 不支持横向扩容和匿名路由。
- 部分终端不能可靠区分 `Shift-Enter` 或 `Shift-Tab`。
- 当前搜索只覆盖已分页加载到内存的消息；可先用 `PageUp` 加载更早历史。

## 许可证

项目使用 `MIT OR Apache-2.0` 双许可证。
