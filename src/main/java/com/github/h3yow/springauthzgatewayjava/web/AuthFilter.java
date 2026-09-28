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
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
 * {@code X-Session-Renewed} 响应头让客户端明确感知续期结果；同时重新下发
 * {@code SESSION} Cookie（Max-Age 与最新失效时间一致），使客户端保存的登录态
 * 与服务端有效期同步延长——空闲超时或到达绝对上限时服务端判定失效，
 * 响应中也会让旧 Cookie 立即过期，两侧一致结束。
 *
 * <p>每个请求分配关联标识（correlation id），日志与错误响应中只出现脱敏后的凭据标识。
 */
public class AuthFilter extends OncePerRequestFilter {

    public static final String CORRELATION_ATTRIBUTE = "correlationId";
    public static final String CORRELATION_HEADER = "X-Correlation-Id";
    public static final String SESSION_COOKIE = "SESSION";
    public static final String SESSION_EXPIRES_AT_HEADER = "X-Session-Expires-At";
    public static final String SESSION_RENEWED_HEADER = "X-Session-Renewed";

    /** 未认证细分原因：对外稳定且可区分。 */
    public enum UnauthenticatedReason { NO_CREDENTIALS, CREDENTIAL_EXPIRED, CREDENTIAL_REVOKED }

    private static final Logger log = LoggerFactory.getLogger(AuthFilter.class);

    private final SessionService sessionService;
    private final TokenService tokenService;
    private final AccessPolicy accessPolicy;
    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * 认证结果：上下文（成功时）、会话续期结果（会话认证时）、失败细分原因、
     * 以及需要在响应中清除的失效会话 Cookie 名称。
     */
    private record AuthOutcome(AuthContext context, SessionService.TouchResult touch,
                               UnauthenticatedReason reason, String staleSessionCookie) {
        static AuthOutcome rejected(UnauthenticatedReason reason, String staleSessionCookie) {
            return new AuthOutcome(null, null, reason, staleSessionCookie);
        }
    }

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
        // 会话滑动续期结果让客户端明确感知，并同步重写客户端 Cookie 的剩余寿命
        if (outcome.touch() != null) {
            SessionRecord touched = outcome.touch().record();
            response.setHeader(SESSION_EXPIRES_AT_HEADER, touched.expiresAt().toString());
            response.setHeader(SESSION_RENEWED_HEADER, String.valueOf(outcome.touch().renewed()));
            response.addHeader("Set-Cookie", syncedSessionCookie(touched));
        }
        // 携带的会话凭据已失效（过期/撤销）：让客户端 Cookie 与服务端一致地结束
        if (outcome.staleSessionCookie() != null
                && !"/api/auth/login".equals(request.getRequestURI())) {
            response.addHeader("Set-Cookie", expireSessionCookie());
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
     * 失效会话 Cookie 即使最终由 Bearer 成功认证，也标记为待清除。
     */
    private AuthOutcome authenticate(HttpServletRequest request) {
        String sessionId = readCookie(request, SESSION_COOKIE);
        String bearer = readBearer(request);
        if (sessionId == null && bearer == null) {
            return AuthOutcome.rejected(UnauthenticatedReason.NO_CREDENTIALS, null);
        }
        UnauthenticatedReason reason = UnauthenticatedReason.CREDENTIAL_REVOKED;
        boolean sessionRejected = false;
        if (sessionId != null) {
            // 先判定（区分过期/撤销）再续期：终态墓碑会让顺序竞争收敛，过期不会被翻转为撤销
            SessionService.Evaluation evaluation = sessionService.evaluate(sessionId);
            if (evaluation.status() == SessionService.SessionStatus.VALID) {
                Optional<SessionService.TouchResult> touched = sessionService.touch(sessionId);
                if (touched.isPresent()) {
                    SessionRecord s = touched.get().record();
                    log.debug("authenticated via session session={} renewed={}",
                            Masking.mask(sessionId), touched.get().renewed());
                    return new AuthOutcome(
                            new AuthContext(s.username(), s.roles(), "session", Masking.mask(sessionId)),
                            touched.get(), null, null);
                }
                // 判定与续期之间被并发撤销：再次确认终态，保证拒绝原因稳定不漂移
                SessionService.SessionStatus afterRace = sessionService.evaluate(sessionId).status();
                if (afterRace == SessionService.SessionStatus.EXPIRED) {
                    reason = UnauthenticatedReason.CREDENTIAL_EXPIRED;
                }
                sessionRejected = true;
            } else if (evaluation.status() == SessionService.SessionStatus.EXPIRED) {
                reason = UnauthenticatedReason.CREDENTIAL_EXPIRED;
                sessionRejected = true;
            } else {
                sessionRejected = true;
            }
            log.info("session credential rejected ({}) session={}", reason, Masking.mask(sessionId));
        }
        if (bearer != null) {
            Optional<TokenService.TokenSubject> subject = tokenService.verifyAccessToken(bearer);
            if (subject.isPresent()) {
                TokenService.TokenSubject t = subject.get();
                log.debug("authenticated via token token={}", Masking.mask(bearer));
                // Bearer 有效但旧会话 Cookie 已失效：清除旧 Cookie，不影响本次认证
                return new AuthOutcome(
                        new AuthContext(t.username(), t.roles(), "token", Masking.mask(bearer)),
                        null, null, sessionRejected ? SESSION_COOKIE : null);
            }
            if (tokenService.evaluateAccessToken(bearer) == TokenService.TokenStatus.EXPIRED) {
                reason = UnauthenticatedReason.CREDENTIAL_EXPIRED;
            }
            log.info("bearer credential rejected ({}) token={}", reason, Masking.mask(bearer));
        }
        return AuthOutcome.rejected(reason, sessionRejected ? SESSION_COOKIE : null);
    }

    /** 续期后重新下发会话 Cookie：Max-Age 严格等于"当前失效时间 - 现在"。 */
    private String syncedSessionCookie(SessionRecord session) {
        long maxAge = Math.max(0, Duration.between(Instant.now(), session.expiresAt()).getSeconds());
        return SESSION_COOKIE + "=" + session.sessionId()
                + "; Path=/; HttpOnly; SameSite=Strict; Max-Age=" + maxAge;
    }

    private static String expireSessionCookie() {
        return SESSION_COOKIE + "=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0";
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
