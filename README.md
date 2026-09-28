# spring-authz-gateway-java

本地可运行的认证与授权子系统（Spring Boot 3 / Java 21，仅依赖 `spring-boot-starter-web`，
不依赖任何外部服务、真实凭据或付费组件）。

## 1. 认证流程

```
POST /api/auth/login                     账号口令登录
POST /api/auth/logout                    登出（撤销会话 + 该用户全部令牌）
POST /api/auth/refresh                   刷新令牌旋转（旧刷新令牌单次使用）
GET  /api/auth/credentials               列举当前用户的活跃凭据（需认证）
DELETE /api/auth/credentials/{id}        撤销单个凭据（需认证，幂等）
POST /api/auth/credentials/revoke-others 撤销除当前外的全部凭据（需认证）
```

- **口令存储**：PBKDF2-HmacSHA256（60k 迭代、随机盐），存储格式
  `pbkdf2$iterations$salt$hash`，常量时间比较；明文不出现在存储、日志与响应中。
- **登录失败分类**（内部日志可区分，对外统一 `INVALID_CREDENTIALS`，不泄露账号是否存在）：
  `ACCOUNT_NOT_FOUND` / `ACCOUNT_DISABLED` / `CREDENTIALS_EXPIRED` / `BAD_PASSWORD` /
  `ACCOUNT_LOCKED`。对不存在账号执行哑散列校验以抹平时序差异。
- **双凭据并存**：登录成功同时签发
  - 有状态会话：`Set-Cookie: SESSION=…; HttpOnly; SameSite=Strict`，CSRF 令牌经 `X-CSRF-Token` 响应头下发；
  - 无状态令牌：HMAC-SHA256 签名的访问/刷新令牌对（`v1.<payload>.<signature>`）。
- **撤销立即生效且终态稳定**：登出或 `revokeAllForUser` 后，会话在注册表原子转为
  REVOKED 墓碑、用户撤销纪元提升，已撤销凭据在任何入口（Cookie 或 Bearer）均返回 401，
  重复请求的拒绝原因保持稳定（详见 1.3）。
- **并发语义**：刷新令牌 jti 注册表原子移除 → 同一刷新令牌并发刷新恰好成功一次，绝不重复签发；
  会话注册表为终态机（`ACTIVE -> EXPIRED / REVOKED`），撤销、过期判定与滑动续期均为
  原子转换，无半更新状态，续期与撤销竞争时终态收敛且以撤销为准。
- **凭据与标识分离**：每个凭据另有公开的 `credentialId`（管理标识），
  与凭据本体（`sessionId`、令牌串、jti）无关；自助管理接口只暴露 `credentialId`。

## 1.1 活跃凭据自助管理

- **列举**：`GET /api/auth/credentials` 返回当前用户全部仍有效的凭据
  （`SESSION` 与 `REFRESH_TOKEN` 两类），每项含
  `credentialId` / `kind` / `client`（登录时的 User-Agent）/
  `issuedAt` / `lastUsedAt` / `expiresAt`；**不含任何凭据本体**。
- **撤销单个**：`DELETE /api/auth/credentials/{credentialId}` 只撤销目标凭据，
  不影响该用户其他客户端；对刷新令牌凭据还会让其派生的访问令牌**立即**失效
  （jti 拒绝名单）。对不存在或不属于当前用户的标识一律返回 204，不泄露归属。
- **撤销其他全部**：`POST /api/auth/credentials/revoke-others` 保留当前请求所用凭据
  （会话 Cookie 或 Bearer 访问令牌所属凭据），其余会话与令牌凭据立即失效。
- **并发收敛**：撤销单个与撤销全部同时发生、或同一凭据被并发重复撤销时，
  注册表原子删除 + 拒绝名单保证最终一致——已撤销凭据不会复活，重复撤销是幂等 no-op。

## 1.2 会话滑动续期（客户端与服务端同步延长、同步结束）

- 会话每次被使用时刷新 `lastUsedAt`；当剩余有效期不足空闲阈值
  （`auth.session-ttl`）的一半时，`expiresAt` 自动顺延为 `now + session-ttl`，
  但**永不超过绝对上限** `createdAt + auth.session-max-lifetime`。
- **客户端登录态随服务端同步延长**：每次会话认证成功的响应都会**重新下发
  `SESSION` Cookie**，其 `Max-Age` 严格等于"服务端当前失效时间 − 当前时刻"。
  因此只要用户持续使用（未空闲超时、未到绝对上限），浏览器保存的登录态就和
  服务端判定的有效期一起向后推，不会在最初登录那一刻算出的过期点被踢下线。
- **两侧一致地结束**：空闲超时或到达绝对上限时，服务端判定失效（401
  `CREDENTIAL_EXPIRED`），响应同时带 `Set-Cookie: SESSION=; Max-Age=0` 清除
  浏览器里的旧 Cookie——不会出现"一边已失效、另一边还带着"的错位；即使请求
  同时带了仍然有效的 Bearer 令牌，失效的旧会话 Cookie 也会在成功响应中被顺带清除
  （登录端点 `/api/auth/login` 除外，那里本就要下发全新 Cookie）。
- **续期结果的感知方式**：
  - `X-Session-Expires-At`：当前（可能已顺延的）失效时间，ISO-8601；
  - `X-Session-Renewed`：本次请求是否真正顺延了失效时间（`true`/`false`）；
  - 两个头与重写后的 `Set-Cookie` 一并出现在每个会话认证的响应中，前端可稳定读取。
- **跨域可见性**：上述两个头以及 `X-Correlation-Id`、`X-CSRF-Token` 均已加入
  CORS 的 `Access-Control-Expose-Headers`（仅对 `auth.allowed-origins` 声明的
  精确来源生效），跨域 XHR/fetch 可以直接读到；携带凭据的跨域请求仍要求
  服务端显式来源且浏览器侧 `credentials: 'include'`。
- 续期与撤销竞争时**以撤销为准**：注册表是
  `ACTIVE -> EXPIRED / REVOKED` 的终态机，续期只在 `ACTIVE` 上做原子替换，
  已撤销（REVOKED 墓碑）或已过期（EXPIRED 墓碑）的会话不会因任何一次续期复活；
  已过期的会话再被撤销仍保持"已过期"，拒绝原因不翻转。

## 1.3 凭据兼容与稳定可区分的 401

- 两类凭据彼此独立：失效的旧会话 Cookie 不会拖累仍然有效的 Bearer 凭据
  （包括 POST 等改变状态请求——失效 Cookie 不触发 CSRF 校验，且会在响应中被清除）；
  携带失效凭据重新登录、刷新令牌或访问公开资源均不受影响。
- 访问受保护资源时，401 响应的 `reason` 字段稳定区分，且**同一凭据在其生命周期内
  重复请求、在不同入口（用户/管理/凭据管理资源）上的拒绝原因保持一致，不漂移**：
  - `NO_CREDENTIALS`：本次请求未携带任何凭据；
  - `CREDENTIAL_EXPIRED`：凭据曾经有效但已过期（空闲超时或到达绝对上限）；
  - `CREDENTIAL_REVOKED`：凭据已撤销，或本就无效/伪造（不泄露凭据与账号信息）。
  响应 `code` 仍为 `UNAUTHENTICATED`，保持向后兼容。
- 实现要点：过期/撤销都会落**终态墓碑**而非简单删除——过期会话首次判定后固定为
  EXPIRED 墓碑（重复请求一直是"过期"，不会第二次变成"撤销"）；撤销固定为
  REVOKED 墓碑。会话墓碑保留到 `max(空闲失效时间, 绝对上限) + 一个空闲 TTL`，
  被撤销的访问令牌在撤销后保留一个访问令牌 TTL 的拒绝名单宽限窗口，且撤销判定
  先于有效期判定，因此"撤销后恰好越过 exp"也不会从"已撤销"漂移成"已过期"。
  墓碑仅在保留窗口之后惰性清理（内存注册表有界）。
- 撤销收敛：单个撤销、撤销其他全部、同一凭据并发重复撤销，全部通过原子终态转换
  收敛到同一个结果；已撤销/已过期凭据不会因续期或重复操作复活。
- 响应体与日志只出现脱敏标识（见第 6 节），绝不出现会话标识、令牌、口令等凭据原文。

## 2. 权限模型

基于角色与资源的判定（`AccessPolicy`），**缺省拒绝**：

| 路径前缀        | 要求                  |
|----------------|-----------------------|
| `/api/public/**` | 公开                |
| `/api/auth/credentials/**` | `USER` 或 `ADMIN`（凭据自助管理） |
| `/api/auth/**`   | 公开                |
| `/api/user/**`   | `USER` 或 `ADMIN`   |
| `/api/admin/**`  | `ADMIN`             |
| 其余任意路径     | 拒绝（`FORBIDDEN_RESOURCE`） |

拒绝原因可区分且稳定：`UNAUTHENTICATED`（401，未认证）与
`FORBIDDEN_ROLE` / `FORBIDDEN_RESOURCE`（403，已认证但越权）严格区分。

## 3. CSRF 与 CORS

- **CSRF**：仅对"携带会话 Cookie 的改变状态请求"（POST/PUT/DELETE/PATCH）强制校验
  `X-CSRF-Token`（常量时间比较）；Bearer 请求与安全方法（GET/HEAD/OPTIONS）豁免。
- **CORS**：仅放行 `auth.allowed-origins` 显式声明的来源（精确匹配、允许凭据）；
  合法预检由 CorsFilter 直接应答（不进入认证过滤器，不被误伤）；未声明来源的预检返回 403。
  `Access-Control-Expose-Headers` 除 `X-CSRF-Token`、`X-Correlation-Id` 外，还包含
  `X-Session-Expires-At` 与 `X-Session-Renewed`，保证跨域前端能读到续期结果。

## 4. 限流与锁定

按 `用户名|客户端IP` 维度统计滑动窗口内失败次数；达到阈值即锁定，
锁定期间**即使凭据正确也返回 429 `ACCOUNT_LOCKED`**（含 `Retry-After`），锁定到期自动恢复，
登录成功清零计数。

## 5. 安全配置项（`application.properties`，前缀 `auth.`）

| 配置项 | 默认 | 说明 |
|--------|------|------|
| `auth.login-max-failures` | 5 | 窗口内最大失败次数 |
| `auth.login-failure-window` | 5m | 失败统计窗口 |
| `auth.lockout-duration` | 10m | 锁定时长 |
| `auth.session-ttl` | 30m | 会话空闲阈值（滑动续期的顺延步长） |
| `auth.session-max-lifetime` | 12h | 会话绝对最长存活时间（续期不得超越） |
| `auth.access-token-ttl` | 10m | 访问令牌有效期 |
| `auth.refresh-token-ttl` | 12h | 刷新令牌有效期 |
| `auth.allowed-origins` | 空 | CORS 允许来源（逗号分隔） |

## 6. 敏感字段脱敏

日志与错误响应中不出现密码、令牌、会话标识原文；以 `sha256:<前8位>…` 形式的
稳定关联标识替代（`Masking`），每个请求另有 `X-Correlation-Id` 关联标识用于排查。

## 7. 内置演示账号（仅本地）

| 用户名 | 口令 | 说明 |
|--------|------|------|
| `alice` | `alice-pass-123` | USER |
| `admin` | `admin-pass-123` | USER + ADMIN |
| `disabled-bob` | `bob-pass-123` | 已停用（不得通过） |
| `expired-carol` | `carol-pass-123` | 凭据已过期（不得通过） |

## 8. 本地验证

```bash
# 运行全部测试（越权/撤销/并发/限流场景为主，单测日志打印输入与判定依据）
mvn test

# 启动应用
mvn spring-boot:run

# 登录
curl -si -X POST localhost:8080/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"alice-pass-123"}'

# 无状态令牌访问
curl -s localhost:8080/api/user/profile -H "Authorization: Bearer <accessToken>"

# 会话访问（改变状态请求需 CSRF 令牌）
curl -s localhost:8080/api/user/profile -H 'Cookie: SESSION=<sessionId>'
curl -s -X POST localhost:8080/api/user/profile \
  -H 'Cookie: SESSION=<sessionId>' -H 'X-CSRF-Token: <csrf>'

# 越权（USER 访问 ADMIN 资源 -> 403 FORBIDDEN_ROLE）
curl -s localhost:8080/api/admin/stats -H "Authorization: Bearer <aliceAccessToken>"

# 登出（撤销后立即生效，两种凭据均 401）
curl -s -X POST localhost:8080/api/auth/logout \
  -H 'Cookie: SESSION=<sessionId>' -H 'X-CSRF-Token: <csrf>'

# 凭据自助管理（列举，只含公开元数据）
curl -s localhost:8080/api/auth/credentials -H "Authorization: Bearer <accessToken>"

# 撤销单个凭据 / 撤销其他全部凭据
curl -s -X DELETE localhost:8080/api/auth/credentials/<credentialId> \
  -H "Authorization: Bearer <accessToken>"
curl -s -X POST localhost:8080/api/auth/credentials/revoke-others \
  -H 'Cookie: SESSION=<sessionId>' -H 'X-CSRF-Token: <csrf>'

# 观察滑动续期：响应头 X-Session-Expires-At / X-Session-Renewed，
# 同时 Set-Cookie 会用最新失效时间重写 SESSION 的 Max-Age（客户端登录态同步延长）
curl -si localhost:8080/api/user/profile -H 'Cookie: SESSION=<sessionId>' | grep -iE 'x-session|set-cookie'

# 三类拒绝原因（重复请求保持稳定）：不带凭据 / 过期 / 撤销
curl -s localhost:8080/api/user/profile                                   # NO_CREDENTIALS
# 等待超过 auth.session-ttl 空闲不活动后再用旧 Cookie：
curl -si localhost:8080/api/user/profile -H 'Cookie: SESSION=<old>'       # CREDENTIAL_EXPIRED + 清除 Cookie
curl -si localhost:8080/api/user/profile -H 'Cookie: SESSION=<revoked>'   # CREDENTIAL_REVOKED + 清除 Cookie

# 跨域读取续期结果（来源需在 auth.allowed-origins 中）
curl -si localhost:8080/api/user/profile \
  -H 'Origin: http://localhost:3000' -H 'Cookie: SESSION=<sessionId>' | grep -i expose

# 短 TTL 本地观察空闲超时 / 绝对上限 / 客户端 Cookie 同步（两种时长可自行调整）：
#   mvn spring-boot:run -Dspring-boot.run.arguments=--auth.session-ttl=10s,--auth.session-max-lifetime=60s
# 持续每 5s 访问一次 -> 一直 200 且 Set-Cookie 不断推后；停止活动超过 10s -> 401 且 Cookie 被清；
# 若持续活动到 60s 绝对上限 -> 同样 401(CREDENTIAL_EXPIRED) 且 Cookie 被清。
```

## 9. 测试结构

- `auth/`：`PasswordHasherTest`、`LoginGuardTest`（阈值/窗口/锁定/自动恢复/并发）、
  `SessionServiceTest`（撤销即时性/并发一致性）、`SessionRenewalTest`（滑动续期：
  空闲阈值/绝对上限/撤销与过期不复活/续期与撤销并发收敛）、
  `RejectionStabilityTest`（同一凭据拒绝原因不漂移：过期会话重复请求恒为 EXPIRED、
  撤销恒为 REVOKED/未知、过期后再撤销不翻转、并发重复撤销收敛、撤销与续期竞争以撤销为准、
  访问令牌"撤销后越过 exp"仍为 INVALID、墓碑保留窗口）、
  `TokenServiceTest`（伪造/过期/旋转/并发刷新恰好一次/并发撤销）、
  `CredentialManagerTest`（凭据列举脱敏/撤销单个/撤销其他全部/并发撤销收敛）、
  `CredentialStatusTest`（有效/过期/撤销三态判定）、
  `AuthServiceTest`（失败分类/锁定/并发登录/失败不污染状态）
- `authz/`：`AccessPolicyTest`（角色矩阵、缺省拒绝、401/403 区分）
- `web/`：`SecurityIntegrationTest`（MockMvc 端到端：越权、撤销、CSRF、CORS 预检、
  429 锁定、刷新旋转、错误响应脱敏）、
  `CredentialLifecycleIntegrationTest`（凭据自助管理端到端、续期响应头、
  失效旧凭据不拖累公开入口与另一类有效凭据、401 细分原因）、
  `SlidingSessionIntegrationTest`（短 TTL 真实等待：持续活跃下重写 Cookie 与
  `X-Session-*` 头、跨越"最初登录过期点"仍保持登录；空闲超时与绝对上限到达时
  401+CREDENTIAL_EXPIRED+清除 Cookie 两侧一致结束；过期旧 Cookie 与有效 Bearer 并存）、
  `RejectionReasonIntegrationTest`（同一过期凭据重复请求/不同入口 reason 不漂移、
  无凭据与已撤销稳定、续期头跨域 Expose-Headers 可见、失效旧凭据与另一类有效凭据并存、
  并发重复撤销经服务层收敛后 HTTP 结果一致）、
  `ExpiredCredentialIntegrationTest`（超短有效期下的 CREDENTIAL_EXPIRED 判定）
- `util/`：`MaskingTest`
