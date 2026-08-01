# Cindy Enterprise Server

一个单进程、单域名的 Cindy 企业服务端参考实现。它直接兼容公开的
`@cindy/device-link-protocol` v1 和当前开源 Desktop/Mobile 客户端，不保存会话正文；
会话历史仍以被控 Desktop 为唯一真相源，服务端只转发加密传输层内的 JSON 帧。

## 已实现

- 企业 OIDC 登录：OIDC discovery、浏览器授权、PKCE、托管 Desktop 回调轮询。
- Cindy access/refresh token：短期 HS256 access token、一次性 refresh token rotation、设备绑定。
- Device Link v1：`hello`、presence、ping/pong、同账号路由、`remoteControlEnabled`、协议错误码、重复连接处理。
- 设备管理：列表、在线状态、重命名、删除、移动推送 token 登记。
- 跨设备附件：本服务提供短期 HMAC 签名 PUT/GET URL、Range 下载、账号隔离和删除。
- 头像上传：公开对象预签名接口，兼容客户端 `ossApiBaseUrl`。
- 企业模型网关：静态凭据下发、模型列表、可选同域反向代理。
- 动态端点清单：`GET /endpoint.json`，所有启用服务都指向同一域名。

以下官方托管产品不属于企业闭环，端点清单默认留空，因此客户端会隐藏或禁用：
OAuth Broker、Slack/Telegram/X Hook、Cindy Voice、GitHub Issue 代理、SkillHub、Plugin Market、
官方计费、官方更新/CDN。移动 APNs/FCM 下发也没有开启；服务端不声明 `notify` capability，
因此现有客户端会安全降级为 App 前台 WS 实时同步。

## 数据边界

服务端持久化：企业身份映射、refresh token 哈希、设备元数据、推送 token、临时媒体。

服务端不持久化：会话消息、Agent 事件、workdir 文件树、远程 IPC 参数。Device Link relay
会在内存里看到这些明文 JSON（TLS 终止后），但只按 `userId + dst` 转发，不解析或落盘。
如果企业安全策略要求 relay 管理员也无法读取正文，需要另外 fork 客户端增加端到端加密；
公开协议和现有客户端目前只有 WSS/TLS，没有 payload E2E。

## 快速启动

1. 复制 `.env.example` 为 `.env`，至少设置 `JWT_SECRET` 和 `PUBLIC_BASE_URL`。
2. 在企业 IdP 创建 OIDC Client，回调地址设为：
   `https://cindy.marlon.life/api/auth/oidc/callback`。
3. 复制 `configs/model-list.example.json` 为 `configs/model-list.json` 并登记网关模型。
4. 用 Caddy、Nginx 或企业网关终止 TLS，并把 HTTP/WebSocket 都转发到 `:8080`。
5. 本地源码启动：`docker compose up --build -d`。

## GitHub Actions 与生产镜像

仓库的 `.github/workflows/server-image.yml` 会先运行 `go test ./...` 和 `go vet ./...`，
再构建 `linux/amd64`、`linux/arm64` 两种架构并推送到：

```text
ghcr.io/marlonfan/cindy-enterprise-server:latest
ghcr.io/marlonfan/cindy-enterprise-server:sha-<commit>
```

推送 `v*` tag 时还会生成同名镜像 tag。生产机使用仓库中的 `compose.prod.yaml`：

```bash
cp .env.example .env
cp configs/model-list.example.json configs/model-list.json
# 编辑 .env、model-list.json；密钥只留在部署机或 Secret Manager。
docker compose -f compose.prod.yaml pull
docker compose -f compose.prod.yaml up -d
```

生产 Compose 只把 Go 服务映射到 `127.0.0.1:8080`。把 `deploy/Caddyfile.example` 放进
宿主机 Caddy 配置后，Caddy 为 `cindy.marlon.life` 自动申请证书，并将普通 HTTP 与
WebSocket 一起反代到 Go 服务。如果 GHCR 包保持 private，生产机需先执行
`docker login ghcr.io`。

本地联调可以不配 OIDC。仅本机访问时设置 `DEV_LOGIN_CODE=123456` 和
`PUBLIC_BASE_URL=http://localhost:8080`；要让同一局域网的手机访问，还需设置：

```dotenv
LISTEN_ADDR=0.0.0.0:8080
PUBLIC_BASE_URL=http://<LAN_IP>:8080
DEV_LOGIN_CODE=123456
```

确认 Windows/macOS 防火墙允许 TCP 8080 入站后运行：

```bash
go run ./cmd/server
```

生产环境必须使用 HTTPS/WSS。正式客户端的端点清单解析会拒绝 HTTP。

## 客户端接线

Dev Desktop 可新建一个不提交 Git 的本地端点文件，把所有启用端点指向本服务：

```json
{
  "schemaVersion": 1,
  "authApiBaseUrl": "http://localhost:8080",
  "authDesktopCallbackUrl": "",
  "deviceLinkApiBaseUrl": "http://localhost:8080",
  "ossApiBaseUrl": "http://localhost:8080",
  "heartbeatUrl": "http://localhost:8080",
  "websiteUrl": "http://localhost:8080",
  "modelAccessApiBaseUrl": "http://localhost:8080"
}
```

再以 `XDT_ENDPOINT_MANIFEST_FILE=<绝对路径>` 启动 Desktop。`authDesktopCallbackUrl` 在本地
设为空可走 loopback 回调；验证企业托管回调时需使用 HTTPS 域名并设为
`https://cindy.marlon.life/api/auth/desktop/callback`。

当前客户端仓也内置了 `dev` 区域工作流。将上述清单保存为 Git 忽略的
`config/endpoint.dev.json` 后，可以直接运行：

```bash
pnpm restart:desktop:remote --region=dev
pnpm mobile:sim:start -- --region=dev --host lan
```

Android Debug 清单默认允许局域网 HTTP；iOS 真机仍受 ATS 约束，非 HTTPS 联调需要在本机
生成的 iOS Debug 工程中加入对应局域网例外。正式企业包仍必须使用 HTTPS/WSS。

正式 Desktop/Mobile 企业构建需要把端点清单 bootstrap base 烘焙为
`https://cindy.marlon.life`。客户端会请求 `https://cindy.marlon.life/endpoint.json`，
以后迁移网关或服务地址只需修改服务端清单，不必重发客户端。

客户端仓还有一处必须同步调整的安全锚点：
`apps/desktop/src/main/endpointManifestCache.ts` 的 `REGION_ENDPOINT_DOMAIN`。企业 Global
构建应把对应 auth realm 改为精确服务域 `cindy.marlon.life`；否则在线启动仍可用，
但网络故障时“使用上次配置启动”会 fail closed，拒绝缓存中的企业端点。不要把它放宽为
公共后缀（例如 `com`），也不要同时信任不相关的多个企业域。

`configs/client-endpoint.build.example.json` 是打包时的参考配置。其中 `cdnBaseUrl` 只用于
把 `/endpoint.json` 的 bootstrap base 烘焙进包体；本服务运行时返回的 `cdnBaseUrl` 为空，
表示企业构建不接官方更新/hotfix 链。

## Android、Windows 与 macOS 客户端

`.github/workflows/client-build.yml` 是企业客户端构建。它不再依赖客户端 fork，也不会在
客户端仓长期提交端点改动。Workflow 启动时只解析一次 `makecindy/cindy` 的最新 `main`
提交，Android、Windows 和 macOS 在同一批构建中固定检出该 SHA，并把实际 SHA 写入
GitHub Actions Summary，随后只在 Actions 临时工作区内完成以下注入：

- 三份客户端自举清单统一指向 `https://cindy.marlon.life`；
- Desktop 离线端点缓存的安全锚点收紧到 `cindy.marlon.life`；
- 使用可与官方客户端并存的 `dev` 构建身份；
- Android 包名使用 `life.marlon.cindy`，且不配置 TapDB 或 Google 登录；
- 保留企业本地验证码登录入口，服务端是否启用仍由 `DEV_LOGIN_CODE` 决定。

每次运行会跟随官方最新 `main`，但单次运行内不会因上游更新而让三端使用不同源码。需要
复现某次构建时，使用 Actions Summary 记录的 SHA；需要长期冻结版本时，可把
`configs/client-build.json` 的 `ref` 临时改成该 40 位 SHA。

桌面打包阶段需要从 GitHub 下载官方 ripgrep 运行资产。Workflow 仅在该构建步骤注入
GitHub 自动令牌，避免共享 Runner 的匿名 API 限流；同时把 `XDT_CDN_BASE_URL` 指向 Cindy
官方 hotfix CDN，在对应版本资产存在时作为下载兜底。这些构建机环境变量不会改写企业
客户端的端点清单，安装后的业务请求仍统一访问 `https://cindy.marlon.life`。

### Android 签名

Android 覆盖升级要求每次使用同一把签名密钥。先在安全目录生成并备份 keystore：

```bash
keytool -genkeypair -v -keystore cindy-enterprise.jks -alias cindy-enterprise \
  -keyalg RSA -keysize 4096 -validity 10000
```

然后在 GitHub 仓库 `Settings -> Secrets and variables -> Actions` 配置：

| Secret | 内容 |
|---|---|
| `ANDROID_KEYSTORE_BASE64` | keystore 文件的 Base64 单行文本 |
| `ANDROID_KEYSTORE_PASSWORD` | keystore 密码 |
| `ANDROID_KEY_ALIAS` | 上例为 `cindy-enterprise` |
| `ANDROID_KEY_PASSWORD` | key 密码 |

PowerShell 生成 Base64：

```powershell
[Convert]::ToBase64String([IO.File]::ReadAllBytes('C:\secure\cindy-enterprise.jks')) |
  Set-Content -NoNewline cindy-enterprise.jks.base64
```

keystore、密码和 Base64 文件都不得提交 Git。丢失 keystore 后无法给已安装客户端做覆盖升级。

### 构建产物与签名状态

在 GitHub Actions 手动运行 `Build enterprise clients`，填写 `version` 和单调递增的
`android_version_code`，并选择需要构建的平台。修改构建 Workflow、配置或注入脚本并推送
到 `main` 时会自动只构建 macOS，方便先验证桌面打包链路。完成后可下载：

- Android：使用上述企业 keystore 签名的 APK；
- Windows：x64 `Setup.exe`，当前未做 Authenticode 签名；
- macOS：x64 和 arm64 DMG，当前仅 ad-hoc 签名、未公证。

未签名 Windows 包会触发 SmartScreen，未公证 macOS 包会触发 Gatekeeper，不适合作为最终
大规模分发形态。取得企业代码签名证书和 Apple Developer ID 后，应把签名凭据接入 Actions；
端点和业务协议无需再修改。

## 模型网关

两种方式二选一：

1. `MODEL_GATEWAY_ENDPOINT` + `MODEL_GATEWAY_CLIENT_KEY`：客户端直接访问既有企业网关。
2. `MODEL_GATEWAY_UPSTREAM` + `MODEL_GATEWAY_UPSTREAM_KEY` +
   `MODEL_GATEWAY_CLIENT_KEY`：客户端访问本服务的 `/api/gateway/*`，本服务验证客户端 key，
   再换成 upstream key 转发。路径和 SSE 响应都原样代理，不做 OpenAI/Anthropic 协议转换；
   Cindy Desktop 自带的本地 bridge 继续负责 Agent 所需的协议适配。

`MODEL_LIST_FILE` 的格式是 `{ "models": [...] }`，字段与客户端
`ModelAccessGatewayModel` 一致。最小必填建议为 `id`、`mode: "chat"`、`name`、
`agents`、`contextWindow`、`efforts` 和 `defaultEffort`。

## 运行约束

- 当前持久化是单节点原子 JSON + 本地媒体目录；relay 在线路由也在进程内存中。
- 因此只能运行一个副本。进程重启不会丢账号、设备或媒体，但在线 WS 会由客户端自动重连。
- 横向扩容时需要把设备连接路由放到 Redis/NATS，把状态迁到 PostgreSQL/Redis，把媒体迁到
  S3/MinIO；客户端和公开协议不需要变化。
- `data/state.json` 权限应限制为服务账号可读，`JWT_SECRET`、OIDC secret 和网关 key 只通过
  Secret Manager/环境变量注入。

## 验证

```bash
gofmt -w .
go test ./...
go vet ./...
```
