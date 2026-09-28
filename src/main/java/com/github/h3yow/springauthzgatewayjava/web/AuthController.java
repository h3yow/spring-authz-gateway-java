package com.github.h3yow.springauthzgatewayjava.web;

import com.github.h3yow.springauthzgatewayjava.auth.AuthFailureReason;
import com.github.h3yow.springauthzgatewayjava.auth.AuthResult;
import com.github.h3yow.springauthzgatewayjava.auth.AuthService;
import com.github.h3yow.springauthzgatewayjava.auth.LoginGuard;
import com.github.h3yow.springauthzgatewayjava.auth.SessionRecord;
import com.github.h3yow.springauthzgatewayjava.auth.TokenService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Arrays;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 登录、登出、令牌刷新端点。
 *
 * <p>对外失败响应统一为 {@code INVALID_CREDENTIALS}，不区分"账号不存在/口令错误/已停用/凭据过期"，
 * 避免泄露账号是否存在；锁定单独返回 {@code ACCOUNT_LOCKED}（429）。
 * 响应与日志中不出现口令、令牌、会话标识原文。
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);

    private final AuthService authService;
    private final TokenService tokenService;
    private final LoginGuard loginGuard;

    public AuthController(AuthService authService, TokenService tokenService, LoginGuard loginGuard) {
        this.authService = authService;
        this.tokenService = tokenService;
        this.loginGuard = loginGuard;
    }

    public record LoginRequest(String username, String password) {}
    public record RefreshRequest(String refreshToken) {}
    public record LoginResponse(String accessToken, String refreshToken, String tokenType) {}

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request, HttpServletRequest http) {
        char[] password = request.password() == null ? new char[0] : request.password().toCharArray();
        try {
            AuthResult result = authService.login(request.username(), password, clientKey(http),
                    clientInfo(http));
            if (!result.success()) {
                return loginFailure(result.failureReason(), request.username(), http);
            }
            SessionRecord session = result.session();
            // 会话 Cookie：HttpOnly + SameSite=Strict，Max-Age 与服务端失效时间对齐
            return ResponseEntity.ok()
                    .header(HttpHeaders.SET_COOKIE, SessionCookies.issue(session))
                    .header(CsrfFilter.CSRF_HEADER, session.csrfToken())
                    .header(AuthFilter.SESSION_EXPIRES_AT_HEADER, session.expiresAt().toString())
                    .header(AuthFilter.SESSION_ABSOLUTE_EXPIRES_AT_HEADER,
                            session.absoluteExpiresAt().toString())
                    .header(AuthFilter.SESSION_RENEWED_HEADER, "true")
                    .body(new LoginResponse(result.accessToken(), result.refreshToken(), "Bearer"));
        } finally {
            Arrays.fill(password, '\0'); // 口令用后即清零
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest http) {
        AuthContext context = (AuthContext) http.getAttribute(AuthContext.REQUEST_ATTRIBUTE);
        String sessionId = readSessionCookie(http);
        authService.logout(sessionId, context != null ? context.username() : null);
        return ResponseEntity.noContent()
                .header(HttpHeaders.SET_COOKIE, SessionCookies.clear())
                .build();
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@RequestBody(required = false) RefreshRequest request,
                                     HttpServletRequest http) {
        String refreshToken = request == null ? null : request.refreshToken();
        if (refreshToken == null || refreshToken.isBlank()) {
            // 未携带凭据：与访问受保护资源时的三态语义保持一致
            return ResponseEntity.status(401).body(new ApiError(
                    "UNAUTHENTICATED", "authentication required", correlationId(http),
                    AuthFilter.UnauthenticatedReason.NO_CREDENTIALS.name()));
        }
        // 先取可区分、稳定的原因（撤销/已用优先于过期），再执行单次使用旋转
        TokenService.RefreshStatus status = tokenService.evaluateRefreshToken(refreshToken);
        return tokenService.refresh(refreshToken)
                .<ResponseEntity<?>>map(pair -> ResponseEntity.ok(
                        new LoginResponse(pair.accessToken(), pair.refreshToken(), "Bearer")))
                .orElseGet(() -> {
                    AuthFilter.UnauthenticatedReason reason =
                            status == TokenService.RefreshStatus.EXPIRED
                                    ? AuthFilter.UnauthenticatedReason.CREDENTIAL_EXPIRED
                                    : AuthFilter.UnauthenticatedReason.CREDENTIAL_REVOKED;
                    log.info("refresh rejected correlation={} reason={}", correlationId(http), reason);
                    return ResponseEntity.status(401).body(new ApiError(
                            "UNAUTHENTICATED", "refresh token invalid, expired or already used",
                            correlationId(http), reason.name()));
                });
    }

    private ResponseEntity<ApiError> loginFailure(AuthFailureReason reason, String username, HttpServletRequest http) {
        String correlationId = correlationId(http);
        if (reason == AuthFailureReason.ACCOUNT_LOCKED || reason == AuthFailureReason.RATE_LIMITED) {
            long retryAfter = loginGuard.lockedSecondsRemaining(username + "|" + clientKey(http));
            log.info("login rejected (locked) user={} correlation={} retryAfter={}s",
                    username, correlationId, retryAfter);
            return ResponseEntity.status(429)
                    .header(HttpHeaders.RETRY_AFTER, String.valueOf(Math.max(1, retryAfter)))
                    .body(new ApiError("ACCOUNT_LOCKED", "too many failed attempts, try again later", correlationId));
        }
        // 其余失败统一为无效凭据，不泄露账号是否存在
        log.info("login rejected user={} correlation={}", username, correlationId);
        return ResponseEntity.status(401).body(
                new ApiError("INVALID_CREDENTIALS", "invalid username or password", correlationId));
    }

    private static String readSessionCookie(HttpServletRequest http) {
        if (http.getCookies() == null) {
            return null;
        }
        for (var c : http.getCookies()) {
            if (AuthFilter.SESSION_COOKIE.equals(c.getName())) {
                return c.getValue();
            }
        }
        return null;
    }

    private static String clientKey(HttpServletRequest http) {
        String forwarded = http.getHeader("X-Forwarded-For");
        return forwarded != null ? forwarded.split(",")[0].trim() : http.getRemoteAddr();
    }

    /** 客户端描述（User-Agent），记入凭据元数据；缺失时记为 unknown。 */
    private static String clientInfo(HttpServletRequest http) {
        String ua = http.getHeader("User-Agent");
        return ua != null && !ua.isBlank() ? ua : "unknown";
    }

    private static String correlationId(HttpServletRequest http) {
        Object id = http.getAttribute(AuthFilter.CORRELATION_ATTRIBUTE);
        return id != null ? id.toString() : "unknown";
    }
}
