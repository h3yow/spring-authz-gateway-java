# spring-authz-gateway-java

本地可运行的认证与授权子系统（Spring Boot 3 / Java 21），不依赖任何外部服务、真实凭据或付费组件。

## 功能概览

- 账号凭据登录/登出，口令以 PBKDF2 散列存储（`spring-security-crypto`），绝不保存明文
- 有状态会话（HttpOnly Cookie）与无状态令牌（HMAC-SHA256 签名）两种访问方式并存
- 基于角色与资源的权限判定，缺省拒绝，未认证（401）与未授权（403）严格区分
- CSRF 同步器令牌防护 + 显式来源白名单的 CORS 控制
- 登录失败限流与账号临时锁定（阈值/窗口/锁定时长均可配置）
- 并发登录、并发刷新、并发撤销下结果一致：刷新令牌原子消费，撤销立即生效
- 敏感字段脱敏：日志与错误响应不含口令/令牌/会话标识原文，仅保留关联标识

## 认证流程

### 会话方式（浏览器）

```
POST /api/auth/login        {"username":"alice","password":"alice-pass-123"}
  ← 200 {"status":"ok","csrfToken":"..."}   + Set-Cookie: SESSION=...; HttpOnly; SameSite=Strict
GET  /api/me                Cookie: SESSION=...
POST /api/documents         Cookie: SESSION=...  +  X-CSRF-Token: <csrfToken>   (改状态请求必须携带)
POST /api/auth/logout       Cookie: SESSION=...  +  X-CSRF-Token: <csrfToken>   (注销立即生效)
```

### 令牌方式（服务间/SPA）

```
POST /api/auth/token          {"username":"bob","password":"bob-pass-123"}
  ← 200 {"accessToken":"...","refreshToken":"...","accessTokenExpiresInSeconds":600}
GET  /api/me                  Authorization: Bearer <accessToken>
POST /api/auth/token/refresh  {"refreshToken":"..."}     (轮换：旧刷新令牌立即作废)
POST /api/auth/token/revoke   Authorization: Bearer <accessToken>   (撤销立即生效)
```

令牌签名密钥在启动时随机生成，应用重启即全部失效；撤销通过服务端登记簿（jti）判定，
已撤销/过期/篡改的令牌在任何入口都会被拒绝。

### 登录失败原因（可区分但不泄露账号存在性）

| 场景 | 错误码 | HTTP |
|---|---|---|
| 账号不存在 / 口令错误 | `INVALID_CREDENTIALS` | 401 |
| 账号已停用 | `ACCOUNT_DISABLED` | 401 |
| 凭据已过期 | `CREDENTIALS_EXPIRED` | 401 |
| 触发锁定（锁定期内凭据正确也拒绝） | `ACCOUNT_LOCKED` | 401 |
| 刷新令牌无效/已消费 | `TOKEN_INVALID` | 401 |

## 权限模型

- 角色 → 权限映射（`RolePermissions`）：权限形如 `resource:action`，支持 `resource:*` 与 `*:*` 通配
  - `ADMIN` → `*:*`
  - `USER` → `profile:read`, `documents:read`
- 端点通过 `@RequiresPermission(resource=..., action=..., role=...)` 声明所需权限
- 判定结果（`AccessDecision`）携带稳定原因：

| 场景 | 原因 | HTTP |
|---|---|---|
| 未携带任何有效凭据 | `UNAUTHENTICATED` | 401 |
| 已认证但缺少必需角色 | `INSUFFICIENT_ROLE` | 403 |
| 已认证但角色未覆盖所需权限 | `MISSING_PERMISSION` | 403 |
| 停用账号/缺省策略 | `DEFAULT_DENY` | 403 |
| 会话方式改状态请求缺少/错误 CSRF 令牌 | `CSRF_TOKEN_INVALID` | 403 |

缺省策略为**拒绝**：未匹配任何授权规则的请求一律不放行。

## 安全配置项（application.properties，`app.security.*`）

| 配置项 | 默认值 | 说明 |
|---|---|---|
| `session-ttl` | `PT30M` | 会话有效期 |
| `access-token-ttl` | `PT10M` | 访问令牌有效期 |
| `refresh-token-ttl` | `PT2H` | 刷新令牌有效期 |
| `allowed-origins` | `http://localhost:3000,http://127.0.0.1:3000` | CORS 允许来源（精确匹配，不用通配符） |
| `login-max-failures` | `5` | 窗口内最大登录失败次数 |
| `login-failure-window` | `PT5M` | 失败统计滑动窗口 |
| `login-lock-duration` | `PT10M` | 触发锁定后的锁定时长（到期自动恢复） |
| `csrf-enabled` | `true` | 是否启用 CSRF 防护 |

## 预置演示账号（仅本地验证用）

| 账号 | 口令 | 角色 | 状态 |
|---|---|---|---|
| `alice` | `alice-pass-123` | ADMIN, USER | 正常 |
| `bob` | `bob-pass-123` | USER | 正常 |
| `carol` | `carol-pass-123` | USER | 已停用 |
| `dave` | `dave-pass-123` | USER | 凭据已过期 |

## 本地验证方法

```bash
# 运行全部测试（56 个：越权/撤销/并发/限流/脱敏/CSRF/CORS）
mvn test

# 启动应用
mvn spring-boot:run

# 冒烟示例
curl -c /tmp/c -X POST localhost:8080/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"alice-pass-123"}'
curl -b /tmp/c localhost:8080/api/me
curl -b /tmp/c localhost:8080/api/admin/stats        # ADMIN 放行
# bob 访问 /api/admin/stats → 403 INSUFFICIENT_ROLE
# 连续 5 次错误口令 → 第 6 次即使口令正确也返回 ACCOUNT_LOCKED
```

## 并发与一致性设计

- 同一用户名的登录按用户级锁串行化，避免限流计数竞态
- 刷新令牌轮换使用 `ConcurrentHashMap.remove(key, value)` 原子消费：N 个并发刷新仅 1 个成功，其余一致失败，不会重复签发
- 会话/令牌注销即物理删除，任何入口再次使用立即失败，不存在半更新状态
- 撤销按用户隔离，`revokeAllForUser` 不影响其他用户的凭据

## 脱敏与可观测性

- 每个请求分配 `X-Correlation-Id`，写入响应头、错误响应体与日志 MDC
- 口令在日志中一律显示为 `***`；令牌/会话标识仅保留前 4 位前缀用于关联排查
- 登录、授权判定均输出结构化日志（判定依据、拒绝原因），错误响应不含敏感原文
