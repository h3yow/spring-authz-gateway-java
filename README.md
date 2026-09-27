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
- **撤销立即生效**：登出或 `revokeAllForUser` 后，会话从注册表原子删除、用户撤销纪元提升，
  已撤销凭据在任何入口（Cookie 或 Bearer）均返回 401。
- **并发语义**：刷新令牌 jti 注册表原子移除 → 同一刷新令牌并发刷新恰好成功一次，绝不重复签发；
  会话/令牌注册表基于 `ConcurrentHashMap`，撤销与校验无半更新状态。
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

## 1.2 会话滑动续期

- 会话每次被使用时刷新 `lastUsedAt`；当剩余有效期不足空闲阈值
  （`auth.session-ttl`）的一半时，`expiresAt` 自动顺延为 `now + session-ttl`，
  但**永不超过绝对上限** `createdAt + auth.session-max-lifetime`。
- 续期结果通过响应头让客户端明确感知：`X-Session-Expires-At`（当前失效时间，
  ISO-8601）与 `X-Session-Renewed`（本次是否真正顺延）；到达绝对上限后
  `expiresAt` 不再移动，客户端可据此提示重新登录。
- 续期与撤销竞争时**以撤销为准**：续期基于 `computeIfPresent` 原子替换，
  已撤销或已过期的会话不会因一次续期复活。

## 1.3 凭据兼容与可区分的 401

- 两类凭据彼此独立：失效的旧会话 Cookie 不会拖累仍然有效的 Bearer 凭据
  （包括 POST 等改变状态请求——失效 Cookie 不触发 CSRF 校验）；
  携带失效凭据重新登录、刷新令牌或访问公开资源均不受影响。
- 访问受保护资源时，401 响应的 `reason` 字段稳定区分：
  `NO_CREDENTIALS`（未携带凭据）、`CREDENTIAL_EXPIRED`（凭据已过期）、
  `CREDENTIAL_REVOKED`（凭据已撤销或无效；为不泄露信息，伪造/未知凭据也归入此类）。
  响应 `code` 仍为 `UNAUTHENTICATED`，保持向后兼容。

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

# 观察滑动续期：响应头 X-Session-Expires-At / X-Session-Renewed
curl -si localhost:8080/api/user/profile -H 'Cookie: SESSION=<sessionId>' | grep -i x-session
```

## 9. 测试结构

- `auth/`：`PasswordHasherTest`、`LoginGuardTest`（阈值/窗口/锁定/自动恢复/并发）、
  `SessionServiceTest`（撤销即时性/并发一致性）、`SessionRenewalTest`（滑动续期：
  空闲阈值/绝对上限/撤销与过期不复活/续期与撤销并发收敛）、
  `TokenServiceTest`（伪造/过期/旋转/并发刷新恰好一次/并发撤销）、
  `CredentialManagerTest`（凭据列举脱敏/撤销单个/撤销其他全部/并发撤销收敛）、
  `CredentialStatusTest`（有效/过期/撤销三态判定）、
  `AuthServiceTest`（失败分类/锁定/并发登录/失败不污染状态）
- `authz/`：`AccessPolicyTest`（角色矩阵、缺省拒绝、401/403 区分）
- `web/`：`SecurityIntegrationTest`（MockMvc 端到端：越权、撤销、CSRF、CORS 预检、
  429 锁定、刷新旋转、错误响应脱敏）、
  `CredentialLifecycleIntegrationTest`（凭据自助管理端到端、续期响应头、
  失效旧凭据不拖累公开入口与另一类有效凭据、401 细分原因）、
  `ExpiredCredentialIntegrationTest`（超短有效期下的 CREDENTIAL_EXPIRED 判定）
- `util/`：`MaskingTest`
