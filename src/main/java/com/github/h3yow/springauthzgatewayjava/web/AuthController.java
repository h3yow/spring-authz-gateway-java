package com.github.h3yow.springauthzgatewayjava.web;

import com.github.h3yow.springauthzgatewayjava.auth.AuthService;
import com.github.h3yow.springauthzgatewayjava.auth.session.SessionService;
import com.github.h3yow.springauthzgatewayjava.auth.token.TokenPair;
import com.github.h3yow.springauthzgatewayjava.auth.token.TokenService;
import com.github.h3yow.springauthzgatewayjava.config.AuthSecurityProperties;
import com.github.h3yow.springauthzgatewayjava.util.Masking;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 认证端点：登录（会话）、登出、令牌签发/刷新/撤销。
 * 响应中绝不包含口令；令牌仅出现在本次响应体内，日志一律脱敏。
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);

    public record LoginRequest(@NotBlank String username, @NotBlank String password) {
        @Override
        public String toString() {
            // 防止口令随日志输出
            return "LoginRequest(username=" + username + ", password=" + Masking.hide(password) + ")";
        }
    }

    public record TokenRequest(@NotBlank String username, @NotBlank String password) {
        @Override
        public String toString() {
            return "TokenRequest(username=" + username + ", password=" + Masking.hide(password) + ")";
        }
    }

    public record RefreshRequest(@NotBlank String refreshToken) {
        @Override
        public String toString() {
            return "RefreshRequest(refreshToken=" + Masking.prefix(refreshToken) + ")";
        }
    }

    private final AuthService authService;
    private final SessionService sessionService;
    private final TokenService tokenService;
    private final AuthSecurityProperties props;

    public AuthController(AuthService authService, SessionService sessionService,
                          TokenService tokenService, AuthSecurityProperties props) {
        this.authService = authService;
        this.sessionService = sessionService;
        this.tokenService = tokenService;
        this.props = props;
    }

    @PostMapping("/login")
    public Map<String, Object> login(@Valid @RequestBody LoginRequest body, HttpServletResponse response) {
        AuthService.LoginOutcome outcome = authService.login(body.username(), body.password());
        if (!outcome.success()) {
            throw AuthException.loginFailed(outcome.failureReason());
        }
        ResponseCookie cookie = ResponseCookie.from(AuthFilter.SESSION_COOKIE, outcome.sessionId())
                .httpOnly(true)
                .sameSite("Strict")
                .path("/")
                .maxAge(props.getSessionTtl())
                .build();
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
        log.info("login issued session user={} session={}", body.username(), Masking.prefix(outcome.sessionId()));
        // CSRF 令牌经响应体下发（双提交之外的同步器模式），供后续改状态请求携带
        return Map.of("status", "ok", "csrfToken", outcome.csrfToken());
    }

    @PostMapping("/logout")
    public Map<String, String> logout(HttpServletRequest request, HttpServletResponse response) {
        AuthContext ctx = AuthContext.from(request);
        if (ctx != null && "session".equals(ctx.credentialKind())) {
            authService.logout(ctx.credentialId());
        }
        Cookie cleared = new Cookie(AuthFilter.SESSION_COOKIE, "");
        cleared.setPath("/");
        cleared.setMaxAge(0);
        cleared.setHttpOnly(true);
        response.addCookie(cleared);
        return Map.of("status", "ok");
    }

    @PostMapping("/token")
    public TokenPair token(@Valid @RequestBody TokenRequest body) {
        AuthService.LoginOutcome outcome = authService.login(body.username(), body.password());
        if (!outcome.success()) {
            throw AuthException.loginFailed(outcome.failureReason());
        }
        // 登录同时签发了会话，令牌方式不需要该会话，立即注销避免凭据堆积
        authService.logout(outcome.sessionId());
        return tokenService.issue(body.username());
    }

    @PostMapping("/token/refresh")
    public TokenPair refresh(@Valid @RequestBody RefreshRequest body) {
        return tokenService.refresh(body.refreshToken())
                .orElseThrow(() -> new AuthException("TOKEN_INVALID", "refresh token invalid, expired or already used"));
    }

    @PostMapping("/token/revoke")
    public Map<String, String> revoke(HttpServletRequest request) {
        AuthContext ctx = AuthContext.from(request);
        if (ctx == null || !"token".equals(ctx.credentialKind())) {
            throw new AuthException("UNAUTHENTICATED", "bearer token required to revoke");
        }
        String header = request.getHeader("Authorization");
        tokenService.revoke(header.substring(7));
        return Map.of("status", "ok");
    }
}
