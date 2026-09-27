# spring-authz-gateway-java

本地可运行的认证与授权子系统（Spring Boot 3 / Java 21，仅依赖 `spring-boot-starter-web`，
不依赖任何外部服务、真实凭据或付费组件）。

## 1. 认证流程

```
POST /api/auth/login        账号口令登录
POST /api/auth/logout       登出（撤销会话 + 该用户全部令牌）
POST /api/auth/refresh      刷新令牌旋转（旧刷新令牌单次使用）
```

- **口令存储**：PBKDF2-HmacSHA256（60k 迭代、随机盐），存储格式
  `pbkdf2$iterations$salt$hash`，常量时间比较；明文不出现在存储、日志与响应中。
- **登录失败分类**（内部日志可区分，对外统一 `INVALID_CREDENTIALS`，不泄露账号是否存在）：
  `ACCOUNT_NOT_FOUND` / `ACCOUNT_DISABLED` / `CREDENTIALS_EXPIRED` / `BAD_PASSWORD` /
  `ACCOUNT_LOCKED`。对不存在账号执行哑散列校验以抹平时序差异。
- **双凭据并存且彼此独立**：登录成功同时签发
  - 有状态会话：`Set-Cookie: SESSION=…; HttpOnly; SameSite=Strict`，CSRF 令牌经 `X-CSRF-Token` 响应头下发；
  - 无状态令牌：HMAC-SHA256 签名的访问/刷新令牌对（`v1.<payload>.<signature>`）。
  携带一种已失效的凭据不会拖累另一种仍然有效的凭据（见第 4 节判定规则）。
- **撤销立即生效**：登出或 `revokeAllForUser` 后，会话翻转为撤销墓碑、用户撤销纪元提升、
  访问令牌元数据原子翻转，已撤销凭据在任何入口（Cookie 或 Bearer）均返回 401，绝不复活。
- **并发语义**：刷新令牌 jti 注册表原子移除 → 同一刷新令牌并发刷新恰好成功一次，绝不重复签发；
  会话/令牌注册表基于 `ConcurrentHashMap`，所有状态迁移（续期/撤销）在 `compute` 内原子完成，
  无半更新状态；撤销与续期竞争时以撤销为准。

## 2. 活跃凭据自助管理

```
GET  /api/user/credentials              查看自己名下当前仍有效的全部凭据
POST /api/user/credentials/revoke       撤销单个凭据        {"id": "<凭据句柄>"}
POST /api/user/credentials/revoke-others 一键撤销除当前凭据外的全部凭据
```

- **视图只含元数据**：每条凭据返回 `id`（对外管理句柄）、`kind`（`SESSION` / `ACCESS_TOKEN`）、
  `clientKey`（签发来源，如客户端 IP）、`issuedAt`、`lastUsedAt`、`expiresAt`。
  会话句柄为独立随机值、令牌句柄为其 jti，均无法还原凭据原文；响应与日志中绝不出现原文。
- **单撤销互不影响**：撤销某个客户端的凭据不影响其他客户端的会话与令牌；
  撤销会话不影响令牌，反之亦然。重复撤销幂等（返回 `{"revoked": false}`）。
- **撤销其余全部**："当前凭据"由服务端从本次请求的认证上下文识别（客户端无需也无法自报）；
  当前凭据是令牌时，其同对刷新令牌一并保留，当前客户端可继续刷新。
- **并发收敛**：单个撤销与"撤销其余全部"近乎同时发生、或同一凭据被并发撤销多次时，
  所有迁移原子完成，最终状态一致——应失效的凭据无一可用，已撤销凭据绝不复活；
  已撤销凭据即使被当作"当前凭据"参数传入也不会被重新激活。
- **归属校验**：只能操作自己名下的凭据，跨用户的撤销请求一律无效。

## 3. 会话滑动续期

- 每次会话被有效使用（通过认证），空闲失效时间自动向后顺延 `auth.session-idle-ttl`；
  空闲超过该阈值即失效。
- 无论怎么续期，会话存活绝不超过自签发起的 `auth.session-max-ttl`（绝对上限）。
- 续期结果通过响应头明确告知客户端，避免"以为还登录着、实际已失效"：
  - `X-Session-Expires-At`：当前（滑动后的）失效时间；
  - `X-Session-Absolute-Expires-At`：绝对上限；
  - `X-Session-Max-Age`：距失效剩余秒数；
  - 同时以下发的 `Set-Cookie` 顺延浏览器 Cookie 有效期。
- 续期与撤销同时发生以撤销为准：已撤销/已过期的会话不会被一次使用重新激活。

## 4. 凭据判定结果（受保护资源 401 的稳定错误码）

| 场景 | 错误码 |
|------|--------|
| 未携带任何凭据 | `CREDENTIAL_MISSING` |
| 凭据曾存在但已被撤销 | `CREDENTIAL_REVOKED` |
| 凭据已超过失效时间 | `CREDENTIAL_EXPIRED` |
| 服务端不认可（伪造/篡改/重启前的旧凭据） | `CREDENTIAL_INVALID` |

- 同时携带多种凭据时，任一有效即认证通过；都失效时按 撤销 > 过期 > 不认可 取最坏结果。
- 这些判定不暴露账号是否存在，响应与日志中不含凭据原文。
- **兼容既有入口**：客户端保存着服务端不再认可的旧凭据（如服务重启后）时，
  重新登录、刷新、访问公开资源均不受旧凭据拖累；携带失效会话 Cookie 的改变状态请求，
  只要带有有效 Bearer 令牌即正常生效（CSRF 校验只针对当前有效的会话 Cookie）。

## 5. 权限模型

基于角色与资源的判定（`AccessPolicy`），**缺省拒绝**：

| 路径前缀        | 要求                  |
|----------------|-----------------------|
| `/api/public/**` | 公开                |
| `/api/auth/**`   | 公开                |
| `/api/user/**`   | `USER` 或 `ADMIN`   |
| `/api/admin/**`  | `ADMIN`             |
| 其余任意路径     | 拒绝（`FORBIDDEN_RESOURCE`） |

未通过授权时的结果可区分且稳定：未认证（401，按第 4 节细分为
`CREDENTIAL_MISSING` / `CREDENTIAL_REVOKED` / `CREDENTIAL_EXPIRED` / `CREDENTIAL_INVALID`）
与已认证但越权（403，`FORBIDDEN_ROLE` / `FORBIDDEN_RESOURCE`）严格区分。

## 6. CSRF 与 CORS

- **CSRF**：仅对"基于<strong>当前有效</strong>会话 Cookie 的改变状态请求"（POST/PUT/DELETE/PATCH）
  强制校验 `X-CSRF-Token`（常量时间比较）；Bearer 请求、安全方法（GET/HEAD/OPTIONS）豁免；
  携带的会话 Cookie 已撤销/过期/不被认可时不再触发拦截，避免旧凭据拖累登录、刷新或 Bearer 请求。
- **CORS**：仅放行 `auth.allowed-origins` 显式声明的来源（精确匹配、允许凭据）；
  合法预检由 CorsFilter 直接应答（不进入认证过滤器，不被误伤）；未声明来源的预检返回 403。

## 7. 限流与锁定

按 `用户名|客户端IP` 维度统计滑动窗口内失败次数；达到阈值即锁定，
锁定期间**即使凭据正确也返回 429 `ACCOUNT_LOCKED`**（含 `Retry-After`），锁定到期自动恢复，
登录成功清零计数。

## 8. 安全配置项（`application.properties`，前缀 `auth.`）

| 配置项 | 默认 | 说明 |
|--------|------|------|
| `auth.login-max-failures` | 5 | 窗口内最大失败次数 |
| `auth.login-failure-window` | 5m | 失败统计窗口 |
| `auth.lockout-duration` | 10m | 锁定时长 |
| `auth.session-ttl` | 30m | 会话有效期（兼容项；滑动续期以 idle/max 两项为准） |
| `auth.session-idle-ttl` | 30m | 会话空闲阈值：空闲超过该时长失效，每次有效使用顺延 |
| `auth.session-max-ttl` | 12h | 会话绝对最长存活：无论如何滑动续期不得超过 |
| `auth.access-token-ttl` | 10m | 访问令牌有效期 |
| `auth.refresh-token-ttl` | 12h | 刷新令牌有效期 |
| `auth.allowed-origins` | 空 | CORS 允许来源（逗号分隔） |

## 9. 敏感字段脱敏

日志与错误响应中不出现密码、令牌、会话标识原文；以 `sha256:<前8位>…` 形式的
稳定关联标识替代（`Masking`），每个请求另有 `X-Correlation-Id` 关联标识用于排查。

## 10. 内置演示账号（仅本地）

| 用户名 | 口令 | 说明 |
|--------|------|------|
| `alice` | `alice-pass-123` | USER |
| `admin` | `admin-pass-123` | USER + ADMIN |
| `disabled-bob` | `bob-pass-123` | 已停用（不得通过） |
| `expired-carol` | `carol-pass-123` | 凭据已过期（不得通过） |

## 11. 本地验证

```bash
# 运行全部测试（越权/撤销/并发/滑动续期/凭据自助管理场景为主，单测日志打印输入与判定依据）
mvn test

# 启动应用
mvn spring-boot:run

# 登录
curl -si -X POST localhost:8080/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"alice-pass-123"}'

# 无状态令牌访问
curl -s localhost:8080/api/user/profile -H "Authorization: Bearer <accessToken>"

# 会话访问（改变状态请求需 CSRF 令牌）；响应头可见滑动续期结果
curl -si localhost:8080/api/user/profile -H 'Cookie: SESSION=<sessionId>' | grep -i x-session
curl -s -X POST localhost:8080/api/user/profile \
  -H 'Cookie: SESSION=<sessionId>' -H 'X-CSRF-Token: <csrf>'

# 查看自己名下全部活跃凭据（仅元数据，无原文）
curl -s localhost:8080/api/user/credentials -H 'Cookie: SESSION=<sessionId>'

# 撤销单个凭据（会话方式调用需 CSRF；用令牌 id 或会话 id 均可）
curl -s -X POST localhost:8080/api/user/credentials/revoke \
  -H 'Content-Type: application/json' -H 'Cookie: SESSION=<sessionId>' \
  -H 'X-CSRF-Token: <csrf>' -d '{"id":"<credentialId>"}'

# 一键撤销除当前凭据外的全部凭据（Bearer 方式无需 CSRF）
curl -s -X POST localhost:8080/api/user/credentials/revoke-others \
  -H "Authorization: Bearer <accessToken>"

# 越权（USER 访问 ADMIN 资源 -> 403 FORBIDDEN_ROLE）
curl -s localhost:8080/api/admin/stats -H "Authorization: Bearer <aliceAccessToken>"

# 携带失效旧凭据访问公开资源/重新登录不受拖累
curl -s localhost:8080/api/public/info -H 'Cookie: SESSION=<revokedSessionId>'

# 登出（撤销后立即生效，两种凭据均 401 CREDENTIAL_REVOKED）
curl -s -X POST localhost:8080/api/auth/logout \
  -H 'Cookie: SESSION=<sessionId>' -H 'X-CSRF-Token: <csrf>'
```

## 12. 测试结构

- `auth/`：`PasswordHasherTest`、`LoginGuardTest`（阈值/窗口/锁定/自动恢复/并发）、
  `SessionServiceTest`（撤销即时性/并发一致性）、`SessionSlidingTest`（空闲滑动阈值/
  绝对上限/撤销与续期竞争以撤销为准/墓碑不复活/撤销其余全部）、
  `TokenServiceTest`（伪造/过期/旋转/并发刷新恰好一次/并发撤销/单令牌撤销隔离/
  REVOKED-EXPIRED-UNKNOWN 判定/保留式撤销/最近使用时间）、
  `CredentialServiceTest`（视图无原文/单撤销隔离/撤销其余全部/跨用户隔离）、
  `CredentialConcurrencyTest`（同凭据并发重复撤销收敛、单个与全部撤销竞争收敛、不复活）、
  `AuthServiceTest`（失败分类/锁定/并发登录/失败不污染状态）
- `authz/`：`AccessPolicyTest`（角色矩阵、缺省拒绝、401/403 区分）
- `web/`：`AuthFilterTest`（四种 401 判定码区分、两类凭据互不拖累、滑动续期响应头）、
  `SecurityIntegrationTest`（MockMvc 端到端：越权、撤销、CSRF、CORS 预检、429 锁定、
  刷新旋转、错误响应脱敏、凭据自助管理端点、旧凭据不拖累、滑动响应头）
- `util/`：`MaskingTest`
