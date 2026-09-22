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
- **双凭据并存**：登录成功同时签发
  - 有状态会话：`Set-Cookie: SESSION=…; HttpOnly; SameSite=Strict`，CSRF 令牌经 `X-CSRF-Token` 响应头下发；
  - 无状态令牌：HMAC-SHA256 签名的访问/刷新令牌对（`v1.<payload>.<signature>`）。
- **撤销立即生效**：登出或 `revokeAllForUser` 后，会话从注册表原子删除、用户撤销纪元提升，
  已撤销凭据在任何入口（Cookie 或 Bearer）均返回 401。
- **并发语义**：刷新令牌 jti 注册表原子移除 → 同一刷新令牌并发刷新恰好成功一次，绝不重复签发；
  会话/令牌注册表基于 `ConcurrentHashMap`，撤销与校验无半更新状态。

## 2. 权限模型

基于角色与资源的判定（`AccessPolicy`），**缺省拒绝**：

| 路径前缀        | 要求                  |
|----------------|-----------------------|
| `/api/public/**` | 公开                |
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
| `auth.session-ttl` | 30m | 会话有效期 |
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
```

## 9. 测试结构

- `auth/`：`PasswordHasherTest`、`LoginGuardTest`（阈值/窗口/锁定/自动恢复/并发）、
  `SessionServiceTest`（撤销即时性/并发一致性）、`TokenServiceTest`（伪造/过期/旋转/
  并发刷新恰好一次/并发撤销）、`AuthServiceTest`（失败分类/锁定/并发登录/失败不污染状态）
- `authz/`：`AccessPolicyTest`（角色矩阵、缺省拒绝、401/403 区分）
- `web/`：`SecurityIntegrationTest`（MockMvc 端到端：越权、撤销、CSRF、CORS 预检、
  429 锁定、刷新旋转、错误响应脱敏）
- `util/`：`MaskingTest`
