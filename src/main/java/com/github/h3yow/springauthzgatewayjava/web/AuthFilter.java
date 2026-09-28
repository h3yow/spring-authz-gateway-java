package com.github.h3yow.springauthzgatewayjava.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.h3yow.springauthzgatewayjava.auth.SessionRecord;
import com.github.h3yow.springauthzgatewayjava.auth.SessionService;
import com.github.h3yow.springauthzgatewayjava.auth.TokenService;
import com.github.h3yow.springauthzgatewayjava.authz.AccessDecision;
import com.github.h3yow.springauthzgatewayjava.authz.AccessPolicy;
import com.github.h3yow.springauthzgatewayjava.util.Masking;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * 认证与授权过滤器。
 *
 * <p>两种访问方式并存且彼此独立：会话 Cookie（{@code SESSION}）或
 * {@code Authorization: Bearer} 令牌；一种凭据失效不影响另一种有效凭据的使用。
 * 已撤销/过期凭据在任何入口一律视为未认证。认证通过后基于角色与资源做授权判定：
 * 未认证返回 401，已认证但越权返回 403，缺省拒绝。
 *
 * <p>401 响应通过 {@code reason} 字段稳定区分：{@code NO_CREDENTIALS}（未携带凭据）、
 * {@code CREDENTIAL_EXPIRED}（凭据已过期）、{@code CREDENTIAL_REVOKED}（凭据已撤销或无效）。
 *
 * <p>会话认证成功时执行滑动续期，并通过 {@code X-Session-Expires-At} /
 * {@code X-Session-Renewed} 响应头让客户端明确感知续期结果。
 *
 * <p>每个请求分配关联标识（correlation id），日志与错误响应中只出现脱敏后的凭据标识。
 */
public class AuthFilter extends OncePerRequestFilter {

    public static final String CORRELATION_ATTRIBUTE = "correlationId";
    public static final String CORRELATION_HEADER = "X-Correlation-Id";
    public static final String SESSION_COOKIE = "SESSION";
    public static final String SESSION_EXPIRES_AT_HEADER = "X-Session-Expires-At";
    public static final String SESSION_ABSOLUTE_EXPIRES_AT_HEADER = "X-Session-Absolute-Expires-At";
    public static final String SESSION_RENEWED_HEADER = "X-Session-Renewed";

    /** 未认证细分原因：对外稳定且可区分。 */
    public enum UnauthenticatedReason { NO_CREDENTIALS, CREDENTIAL_EXPIRED, CREDENTIAL_REVOKED }

    private static final Logger log = LoggerFactory.getLogger(AuthFilter.class);

    private final SessionService sessionService;
    private final TokenService tokenService;
    private final AccessPolicy accessPolicy;
    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * 认证结果：上下文（成功时）、会话续期结果（会话认证时）、失败细分原因，
     * 以及是否需要清除浏览器侧失效会话 Cookie。
     */
    private record AuthOutcome(AuthContext context, SessionService.TouchResult touch,
                               UnauthenticatedReason reason, boolean clearSessionCookie) {}

    public AuthFilter(SessionService sessionService, TokenService tokenService, AccessPolicy accessPolicy) {
        this.sessionService = sessionService;
        this.tokenService = tokenService;
        this.accessPolicy = accessPolicy;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String correlationId = UUID.randomUUID().toString();
        request.setAttribute(CORRELATION_ATTRIBUTE, correlationId);
        response.setHeader(CORRELATION_HEADER, correlationId);

        AuthOutcome outcome = authenticate(request);
        if (outcome.context() != null) {
            request.setAttribute(AuthContext.REQUEST_ATTRIBUTE, outcome.context());
        }
        // 登出由控制器显式终结会话：不重发滑动 Cookie，避免与清除指令并列
        boolean logoutPath = "POST".equals(request.getMethod())
                && "/api/auth/logout".equals(request.getRequestURI());
        // 会话滑动续期结果让客户端明确感知（含跨域，见 CORS exposed-headers）
        if (outcome.touch() != null && !logoutPath) {
            SessionRecord record = outcome.touch().record();
            response.setHeader(SESSION_EXPIRES_AT_HEADER, record.expiresAt().toString());
            response.setHeader(SESSION_ABSOLUTE_EXPIRES_AT_HEADER, record.absoluteExpiresAt().toString());
            response.setHeader(SESSION_RENEWED_HEADER, String.valueOf(outcome.touch().renewed()));
            // 关键：每次会话请求都按当前服务端失效时间重新下发 Cookie，
            // 浏览器 Cookie 的存活时间随之滑动，与服务端一致地延长。
            response.addHeader(HttpHeaders.SET_COOKIE, SessionCookies.issue(record));
        }
        // 服务端判定会话凭据已终结（过期/撤销）时，立即清除浏览器侧登录态，两端一致结束。
        // 登出路径的清除指令由控制器自身下发，这里不重复。
        if (outcome.clearSessionCookie() && !logoutPath) {
            response.addHeader(HttpHeaders.SET_COOKIE, SessionCookies.clear());
        }

        boolean authenticated = outcome.context() != null;
        Set<com.github.h3yow.springauthzgatewayjava.auth.Role> roles =
                authenticated ? outcome.context().roles() : Set.of();
        AccessDecision decision = accessPolicy.decide(
                request.getMethod(), request.getRequestURI(), roles, authenticated);
        if (!decision.permitted()) {
            log.info("request denied correlation={} path={} reason={}",
                    correlationId, request.getRequestURI(), decision.denyReason());
            writeDenial(response, decision.denyReason(), outcome.reason(), correlationId);
            return;
        }
        chain.doFilter(request, response);
    }

    /**
     * 依次尝试会话 Cookie 与 Bearer 令牌；任一有效即认证成功。
     * 均失败时按"已过期优先于已撤销"归类细分原因；未携带任何凭据则为 NO_CREDENTIALS。
     */
    private AuthOutcome authenticate(HttpServletRequest request) {
        String sessionId = readCookie(request, SESSION_COOKIE);
        String bearer = readBearer(request);
        if (sessionId == null && bearer == null) {
            return new AuthOutcome(null, null, UnauthenticatedReason.NO_CREDENTIALS, false);
        }
        UnauthenticatedReason reason = UnauthenticatedReason.CREDENTIAL_REVOKED;
        boolean sessionPresented = sessionId != null;
        if (sessionId != null) {
            // 判定 + 续期原子完成：不存在二者之间被并发撤销而漂移的窗口
            SessionService.SessionAuthResult auth = sessionService.authenticate(sessionId);
            if (auth.status() == SessionService.SessionStatus.VALID && auth.touch() != null) {
                SessionRecord s = auth.touch().record();
                log.debug("authenticated via session session={} renewed={}",
                        Masking.mask(sessionId), auth.touch().renewed());
                return new AuthOutcome(
                        new AuthContext(s.username(), s.roles(), "session", Masking.mask(sessionId)),
                        auth.touch(), null, false);
            }
            if (auth.status() == SessionService.SessionStatus.EXPIRED) {
                reason = UnauthenticatedReason.CREDENTIAL_EXPIRED;
            }
            log.info("session credential rejected ({}) session={}", reason, Masking.mask(sessionId));
        }
        if (bearer != null) {
            Optional<TokenService.TokenSubject> subject = tokenService.verifyAccessToken(bearer);
            if (subject.isPresent()) {
                TokenService.TokenSubject t = subject.get();
                log.debug("authenticated via token token={}", Masking.mask(bearer));
                return new AuthOutcome(
                        new AuthContext(t.username(), t.roles(), "token", Masking.mask(bearer)),
                        null, null, false);
            }
            if (tokenService.evaluateAccessToken(bearer) == TokenService.TokenStatus.EXPIRED) {
                reason = UnauthenticatedReason.CREDENTIAL_EXPIRED;
            }
            log.info("bearer credential rejected ({}) token={}", reason, Masking.mask(bearer));
        }
        // 携带了失效会话 Cookie 且最终未认证：终结浏览器侧登录态（有效 Bearer 成功时不会走到这里）
        return new AuthOutcome(null, null, reason, sessionPresented);
    }

    private void writeDenial(HttpServletResponse response, AccessDecision.DenyReason reason,
                             UnauthenticatedReason unauthenticatedReason, String correlationId)
            throws IOException {
        int status = reason == AccessDecision.DenyReason.UNAUTHENTICATED ? 401 : 403;
        ApiError error = new ApiError(reason.name(),
                reason == AccessDecision.DenyReason.UNAUTHENTICATED
                        ? "authentication required" : "access denied",
                correlationId,
                reason == AccessDecision.DenyReason.UNAUTHENTICATED && unauthenticatedReason != null
                        ? unauthenticatedReason.name() : null);
        response.setStatus(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write(objectMapper.writeValueAsString(error));
    }

    private static String readCookie(HttpServletRequest request, String name) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return null;
        }
        for (Cookie c : cookies) {
            if (name.equals(c.getName())) {
                return c.getValue();
            }
        }
        return null;
    }

    private static String readBearer(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        if (header != null && header.startsWith("Bearer ")) {
            return header.substring(7).trim();
        }
        return null;
    }
}
