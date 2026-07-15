# Sanctum · 个人密钥保险库（Secrets Vault）

Sanctum 是 Steadholme 主权基础设施中的**个人密钥保险库（secrets vault）**服务，部署于
`vault.w33d.xyz`，内部监听端口 `8990`。它由 Sluice 网关以 `auth=sso` 方式托管：网关完成 OIDC
浏览器登录，剥离入站的 `X-Auth-*`，并注入经过校验的 `X-Auth-Subject` / `X-Auth-Email`。Sanctum
自身**不做任何登录**，它信任这些请求头作为已登录的管理员（admin）。

服务遵循 Steadholme 共享模板：Rust + axum、async-trait 的 Postgres 存储层（内存 + PgStore，运行期
SQL、无编译期宏、无 `block_in_place`）、独立数据库 `sanctum`、幂等迁移、企业级 Steadholme UI、POST
接口的 CSRF 防护、对所有不可信内容做转义、`healthcheck` 子命令、多阶段非 root 镜像、`GET /healthz`
存活探针。

## 核心特性

- **静态加密（encryption at rest）**：每个密钥**值**都用 **AES-256-GCM** 加密后才落库。密钥从环境变量
  `MASTER_KEY` 经域分隔的 KDF（`SHA-256("sanctum-kdf-v1\0" || context || "\0" || master)`）派生，
  **绝不**直接使用 master key 作为 AES key。每次封装使用**全新随机 96-bit nonce**，列中存放的是
  `base64(nonce || 密文+GCM tag)`——**明文从不入库、从不打印**。
- **版本化**：对同一 path 再次写入会追加一个**新版本**（`latest + 1`），旧版本保留在历史中。
- **揭示即审计（reveal is auditable）**：`GET /s/{path}` 会服务端解密并返回最新值——这是一次**显式、敏感**
  操作，会异步上报 Watchtower 审计链（记录**谁/哪个 path/何时/版本号**，**绝不**记录明文）。
- **Transit API**：供其他服务调用的 `POST /transit/encrypt` / `POST /transit/decrypt`，使用**命名 transit
  key**，可用内部令牌 `TRANSIT_TOKEN`（而非 SSO）鉴权。密文是自描述的 `sanctum:v1:{key}:{base64}`。
- **企业 UI**：保险库列表只显示**遮罩**（`••••`）的占位，打开某个密钥后值默认**遮罩**，点击 **Reveal** 才显示、
  并支持 **Copy** 一键复制。

## 数据模型（db `sanctum`）

```text
secrets(
  path TEXT, version BIGINT, ciphertext TEXT, created_at BIGINT, created_by TEXT,
  PRIMARY KEY (path, version)
)
secret_meta(
  path TEXT PRIMARY KEY, latest_version BIGINT, updated_at BIGINT
)
```

- `ciphertext` 永远是 `base64(nonce || AES-256-GCM(value))` 的封装值，**绝非**明文。
- 迁移幂等（`CREATE TABLE IF NOT EXISTS`），可在每次启动时安全执行。
- 仅使用可移植标准 SQL（TEXT/BIGINT、PRIMARY KEY、`INSERT .. ON CONFLICT`、事务），将来可在 FusionDB
  上经 pgwire 原样运行。

## 接口

| 方法 + 路径 | 鉴权 | 说明 |
|---|---|---|
| `GET /healthz` | 公开 | 存活探针（容器 HEALTHCHECK 使用） |
| `GET /` | SSO | 保险库列表：path + 最新版本，**不含值** |
| `POST /` | SSO + CSRF | 新建/更新密钥（`path` + `value`）→ 302 到详情页 |
| `GET /s/{path}` | SSO | **揭示**最新值（解密 + **审计**）+ 版本历史 + 新增版本表单 + 删除 |
| `POST /s/{path}` | SSO + CSRF | 写入一个新版本 → 302 到详情页 |
| `POST /s/{path}/delete` | SSO + CSRF | 删除该 path 及其**全部版本** → 302 `/` |
| `GET /s/{path}/v/{version}` | SSO | **揭示**某个历史版本（解密 + **审计**） |
| `POST /transit/encrypt` | Token 或 SSO | 用命名 transit key 封装 `{plaintext, key?}` → `{ciphertext, key}` |
| `POST /transit/decrypt` | Token 或 SSO | 解开 `sanctum:v1:...` 令牌 `{ciphertext}` → `{plaintext}` |

> **path 中的斜杠**：层级化 path（如 `db/prod/password`）在 URL 中作为**单个百分号编码**的路由段传入
> （`db%2Fprod%2Fpassword`），`Path` 提取器会解码还原。path 校验：`[A-Za-z0-9._/-]`、长度 ≤ 256、
> 不以 `/` 开头或结尾、无空段 / `.` / `..`。

### Transit 鉴权两种路径

1. **SSO**：经 Sluice 网关注入了 `X-Auth-Subject`（管理员在浏览器里测试）。
2. **内部令牌**：`Authorization: Bearer <TRANSIT_TOKEN>`，供 `holdfast` 网络内**直连** Sanctum 的服务到服务
   调用（不走 SSO 网关）。

未配置 `TRANSIT_TOKEN` 时仅 SSO 路径有效。v1 将 transit 路由与 SSO 应用同处一体，并额外支持内部令牌模式。

## 环境变量

| 变量 | 默认 | 说明 |
|---|---|---|
| `BIND_ADDR` | `0.0.0.0:8990` | 监听地址 |
| `PUBLIC_BASE_URL` | `https://vault.w33d.xyz` | 公开基址（仅用于 UI 链接） |
| `SANCTUM_STORE` | `memory` | `memory` \| `postgres` |
| `DATABASE_URL` | — | `SANCTUM_STORE=postgres` 时必填 |
| `MASTER_KEY` | —（postgres 时**必填**） | 静态加密主密钥；postgres 模式下缺失会**拒绝启动**（绝不用 dev key 落库） |
| `TRANSIT_KEY` | `default` | transit 默认 key 名 |
| `TRANSIT_TOKEN` | —（可选） | transit 内部令牌；设置后启用 Bearer 鉴权路径 |
| `AUDIT_ENABLED` | `off` | 置 `on` 开启 Watchtower 审计上报 |
| `WATCHTOWER_URL` | — | 例如 `http://watchtower:8500` |
| `AUDIT_INGEST_TOKEN` | — | Watchtower `POST /events` 的 Bearer 令牌 |

> **Shamir 解封（unseal）暂缓**：v1 直接从 `MASTER_KEY` 取主密钥；Shamir 分片解封是后续工作。

## 安全说明（security_notes）

- 主密钥来自环境变量 `MASTER_KEY`（Shamir 解封暂缓）；postgres 模式缺失即拒绝启动。
- 密钥值以 **AES-256-GCM** 静态加密，**每条密钥独立随机 nonce**；列中只存 `base64(nonce||密文)`。
- **明文绝不入库、绝不写日志**；审计事件只含 `actor/action/target(path)/severity/detail`，不含值。
- **揭示可审计**：`GET /s/{path}` 与 `GET /s/{path}/v/{version}` 都会上报 `secret.reveal`。
- 列表页永不返回值；详情页的值放在 `data-value` 属性中并经 HTML 转义，默认遮罩、点击才显示。
- 所有 POST（新建/写入/删除）使用 `__Host-csrf` 双提交（double-submit）CSRF 防护，常量时间比较。
- GCM 认证 tag 使**篡改或错误主密钥**变为硬性解密失败，而非静默返回错误明文。

## 本地开发与测试

默认（内存存储 + dev 主密钥，无需数据库 / 网络）：

```bash
cargo run                 # 监听 0.0.0.0:8990，使用 dev 身份回退
cargo test                # DB-free 单测 + 端到端流程（含 transit、CSRF、斜杠 path 路由）
cargo clippy --all-targets -- -D warnings
```

Postgres 集成测试（需要一个一次性 Postgres）：

```bash
docker run --rm -d --name sanctum-testpg -e POSTGRES_PASSWORD=pw -e POSTGRES_DB=sanctum \
  -p 127.0.0.1:55490:5432 postgres:18-alpine
TEST_DATABASE_URL=postgres://postgres:pw@127.0.0.1:55490/sanctum \
  cargo test --test pg_integration -- --nocapture
docker rm -f sanctum-testpg
```

## 构建镜像

```bash
docker build -t steadholme/sanctum:dev .
docker run --rm -p 127.0.0.1:8990:8990 steadholme/sanctum:dev
curl -s http://127.0.0.1:8990/healthz   # -> ok
```

## 部署接入（交给 deploy）

- **数据库**：`sanctum`（Shared Postgres，host `postgres`，user `holdfast`，独立 database）。
- **端口**：内部 `8990`，仅在 `holdfast` 网络内可达（不对外发布端口）。
- **路由**：`vault.w33d.xyz` → `http://sanctum:8990`，`auth=sso`（无 public 子路径）。
- **Portal 磁贴**：`Vault`。**Beacon 组件**：`Vault`。
- **额外环境变量**：`MASTER_KEY`（必填）、`SANCTUM_STORE=postgres`、`DATABASE_URL`（指向 `sanctum` 库）、
  `AUDIT_ENABLED=on` + `WATCHTOWER_URL=http://watchtower:8500` + `AUDIT_INGEST_TOKEN`；可选
  `TRANSIT_TOKEN`（供服务到服务 transit 调用）。
