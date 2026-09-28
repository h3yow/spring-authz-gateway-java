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

## 1.2 会话滑动续期（客户端与服务端一致滑动）

- 会话每次被使用时刷新 `lastUsedAt`；当剩余有效期不足空闲阈值
  （`auth.session-ttl`）的一半时，`expiresAt` 自动顺延为 `now + session-ttl`，
  但**永不超过绝对上限** `createdAt + auth.session-max-lifetime`。
- **客户端侧行为（本次修复重点）**：认证过滤器对每个会话认证成功的响应都
  **重新下发同名 `SESSION` Cookie**，其 `Max-Age` 按
  `X-Session-Expires-At − 当前时刻`重新计算。因此浏览器保存的登录态不再停在
  最初登录那一刻算出的过期点，而是与服务端判定的有效期**一致地滑动延长**。
  会话标识（Cookie 值）在续期中保持不变，不会因续期产生新凭据。
- **续期结果的感知方式**：每个会话响应都稳定携带
  - `X-Session-Expires-At`：当前（可能被顺延的）空闲失效时间，ISO-8601；
  - `X-Session-Absolute-Expires-At`：绝对上限（永不变动），前端可据此提前提示重新登录；
  - `X-Session-Renewed`：本次请求是否真正顺延了过期时间（`true`/`false`）。
  三个头均已加入 CORS `Access-Control-Expose-Headers`，**跨域前端可直接读取**
  （来源仍须在 `auth.allowed-origins` 中声明且请求带凭据）。
- **两端一致地结束**：
  - 空闲超时：浏览器 Cookie 的 `Max-Age` 本就在该时刻归零，本地登录态同时消失；
    若客户端仍重放旧凭据，服务端稳定返回 401 `CREDENTIAL_EXPIRED`，并下发
    `Max-Age=0` 的 Cookie 立即清掉残留；
  - 绝对上限：即使持续活跃，越过 `X-Session-Absolute-Expires-At` 后服务端判定过期、
    续期不再顺延，并同样清除客户端 Cookie；
  - 登出/撤销：控制器与过滤器只下发清除指令，不下发滑动 Cookie。
- 续期与撤销竞争时**以撤销为准**：判定与续期在同一个原子操作内完成
  （`SessionService.authenticate` 的 `compute`），已撤销（记录删除）或已过期
  （墓碑保留）的会话不会因一次续期复活。

## 1.3 凭据兼容与可区分、稳定的 401

- 两类凭据彼此独立：失效的旧会话 Cookie 不会拖累仍然有效的 Bearer 凭据
  （包括 POST 等改变状态请求——失效 Cookie 不触发 CSRF 校验）；
  携带失效凭据重新登录、刷新令牌或访问公开资源均不受影响。
- 访问受保护资源时，401 响应的 `reason` 字段稳定区分三类语义：
  - `NO_CREDENTIALS`：未携带任何凭据（刷新端点请求体为空时同样如此）；
  - `CREDENTIAL_EXPIRED`：凭据曾有效、但已越过自身失效时间（**空闲超时或绝对上限**）；
  - `CREDENTIAL_REVOKED`：凭据已撤销、刷新令牌已旋转消费/已用、或伪造/未知/畸形
    （为不泄露账号/凭据是否存在，未知凭据也归入此类）。
- **同一凭据的拒绝原因在其生命周期内保持稳定（本次修复重点）**：
  - 过期会话不再在首次判定时被惰性删除——它作为**过期墓碑**保留
    （保留到绝对上限之后再额外保留 `auth.revocation-retention`，默认 24h），
    因此同一个过期会话无论重复请求多少次、换哪个受保护入口，始终是
    `CREDENTIAL_EXPIRED`，不会第二次漂移成"已撤销"；
  - 令牌侧**撤销判定优先于自然过期**：被撤销的访问/刷新令牌即使随后越过自身
    过期点，仍稳定返回 `CREDENTIAL_REVOKED`；撤销信息（用户撤销纪元、jti 拒绝名单、
    刷新 jti 消费墓碑）在"自然过期 + 保留期"内不清除；未被撤销的过期令牌则稳定
    返回 `CREDENTIAL_EXPIRED`；
  - `/api/auth/refresh` 同样以 `reason` 稳定区分：缺失 = `NO_CREDENTIALS`，
    未撤销的过期刷新令牌 = `CREDENTIAL_EXPIRED`，已撤销/已旋转消费/无效 =
    `CREDENTIAL_REVOKED`（重复消费已用刷新令牌不会漂移成 EXPIRED）。
  - 所有 401 响应的 `code` 仍为 `UNAUTHENTICATED`，保持向后兼容；响应与日志中
    只出现脱敏标识，绝不出现会话 ID、jti、令牌串原文。

### 撤销收敛与旧凭据隔离

- **撤销与续期竞争以撤销为准**：续期不可能让已撤销或已过期的凭据复活
  （原子 `compute` + 记录删除语义）。
- 单个撤销、撤销其他全部、同一凭据被并发重复撤销，最终都收敛到同一个结果：
  目标凭据在所有入口稳定失效（会话 = 记录删除 → UNKNOWN/`CREDENTIAL_REVOKED`；
  访问令牌 = jti 拒绝名单 + 用户撤销纪元 → INVALID/`CREDENTIAL_REVOKED`）。
  重复撤销是幂等 no-op。
- **旧失效凭据不影响新流程**：带着已失效会话 Cookie 或已失效访问令牌时，
  重新登录、刷新访问、访问公开资源均照常；同时带着另一种仍有效的凭据做改变
  状态请求时（如失效会话 Cookie + 有效 Bearer POST），旧凭据既不触发 CSRF、
  也不改变认证结果，状态变更正常完成。

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
  `Access-Control-Expose-Headers` 暴露 `X-CSRF-Token`、`X-Correlation-Id` 以及
  会话续期感知头 `X-Session-Expires-At` / `X-Session-Absolute-Expires-At` /
  `X-Session-Renewed`，跨域前端可直接读取；跨域带凭据请求的滑动 `Set-Cookie`
  由浏览器自动应用（同源部署时 SameSite=Strict 即可，跨站需结合 SameSite=None; Secure）。

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
| `auth.revocation-retention` | 24h | 撤销/过期墓碑保留时长：窗口内同一凭据的拒绝原因稳定不漂移 |
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

# 观察滑动续期：响应头 X-Session-Expires-At / X-Session-Absolute-Expires-At / X-Session-Renewed，
# 以及每次被重新下发、Max-Age 随之延长的 SESSION Cookie
curl -si localhost:8080/api/user/profile -H 'Cookie: SESSION=<sessionId>' | grep -iE 'x-session|set-cookie'

# 客户端一致性与稳定拒绝原因（用短 TTL 本地观察）：
#   mvn spring-boot:run -Dspring-boot.run.arguments="--auth.session-ttl=8s --auth.session-max-lifetime=30s"
# 1) 每 2~3s 持续访问：X-Session-Renewed 在剩余过半时变 true，Set-Cookie 的 Max-Age 重新变大；
# 2) 空闲超过 8s：浏览器 Cookie 自行失效；手动重放旧 Cookie 时服务端稳定返回
#    reason=CREDENTIAL_EXPIRED 且 Set-Cookie: Max-Age=0，重复多次原因不漂移；
# 3) 每 2s 持续访问越过 30s 绝对上限：稳定 CREDENTIAL_EXPIRED + 清除 Cookie；
# 4) 登出后重放旧 Cookie：稳定 reason=CREDENTIAL_REVOKED；
# 5) 跨域：带 Origin: http://localhost:3000 请求，可见 Access-Control-Expose-Headers 含三个 X-Session-* 头。
```

## 9. 测试结构

- `auth/`：`PasswordHasherTest`、`LoginGuardTest`（阈值/窗口/锁定/自动恢复/并发）、
  `SessionServiceTest`（撤销即时性/并发一致性）、`SessionRenewalTest`（滑动续期：
  空闲阈值/绝对上限/撤销与过期不复活/续期与撤销并发收敛）、
  `SessionReasonStabilityTest`（**同一过期凭据重复判定稳定 EXPIRED、撤销优先于过期、
  墓碑保留窗口**）、
  `TokenServiceTest`（伪造/过期/旋转/并发刷新恰好一次/并发撤销）、
  `TokenReasonStabilityTest`（**撤销令牌越过自然过期仍稳定 INVALID、过期稳定 EXPIRED、
  刷新令牌消费后稳定 INVALID**）、
  `RevocationConvergenceTest`（**单个/撤销全部/并发重复撤销收敛、续期不复活已撤销或已过期凭据**）、
  `CredentialManagerTest`（凭据列举脱敏/撤销单个/撤销其他全部/并发撤销收敛）、
  `CredentialStatusTest`（有效/过期/撤销三态判定）、
  `AuthServiceTest`（失败分类/锁定/并发登录/失败不污染状态）
- `authz/`：`AccessPolicyTest`（角色矩阵、缺省拒绝、401/403 区分）
- `web/`：`SecurityIntegrationTest`（MockMvc 端到端：越权、撤销、CSRF、CORS 预检与
  续期头跨域暴露、429 锁定、刷新旋转、错误响应脱敏）、
  `CredentialLifecycleIntegrationTest`（凭据自助管理端到端、续期响应头、
  失效旧凭据不拖累公开入口与另一类有效凭据、401 细分原因）、
  `ExpiredCredentialIntegrationTest`（超短有效期下的 CREDENTIAL_EXPIRED 判定、
  **同一过期会话/令牌重复请求与不同入口原因不漂移**、刷新端点三类原因）、
  `SessionSlidingCookieIntegrationTest`（**客户端 Cookie Max-Age 随服务端失效时间
  同步滑动、空闲超时与绝对上限两端一致结束、跨域可见性**）、
  `CredentialRaceIntegrationTest`（**HTTP 级续期与撤销竞争收敛、
  失效旧会话 + 有效 Bearer 改变状态不受影响**）
- `util/`：`MaskingTest`
