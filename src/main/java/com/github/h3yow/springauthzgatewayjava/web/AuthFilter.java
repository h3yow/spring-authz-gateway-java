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
import org.springframework.http.MediaType;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * 认证与授权过滤器。
 *
 * <p>两种访问方式并存：会话 Cookie（{@code SESSION}）或 {@code Authorization: Bearer} 令牌。
 * 已撤销/过期凭据在任何入口一律视为未认证。认证通过后基于角色与资源做授权判定：
 * 未认证返回 401，已认证但越权返回 403，缺省拒绝。
 *
 * <p>每个请求分配关联标识（correlation id），日志与错误响应中只出现脱敏后的凭据标识。
 */
public class AuthFilter extends OncePerRequestFilter {

    public static final String CORRELATION_ATTRIBUTE = "correlationId";
    public static final String CORRELATION_HEADER = "X-Correlation-Id";
    public static final String SESSION_COOKIE = "SESSION";

    private static final Logger log = LoggerFactory.getLogger(AuthFilter.class);

    private final SessionService sessionService;
    private final TokenService tokenService;
    private final AccessPolicy accessPolicy;
    private final ObjectMapper objectMapper = new ObjectMapper();

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

        AuthContext context = authenticate(request);
        if (context != null) {
            request.setAttribute(AuthContext.REQUEST_ATTRIBUTE, context);
        }

        boolean authenticated = context != null;
        Set<com.github.h3yow.springauthzgatewayjava.auth.Role> roles =
                authenticated ? context.roles() : Set.of();
        AccessDecision decision = accessPolicy.decide(
                request.getMethod(), request.getRequestURI(), roles, authenticated);
        if (!decision.permitted()) {
            log.info("request denied correlation={} path={} reason={}",
                    correlationId, request.getRequestURI(), decision.denyReason());
            writeDenial(response, decision.denyReason(), correlationId);
            return;
        }
        chain.doFilter(request, response);
    }

    /** 依次尝试会话 Cookie 与 Bearer 令牌；任一有效即认证成功，均失败则未认证。 */
    private AuthContext authenticate(HttpServletRequest request) {
        String sessionId = readCookie(request, SESSION_COOKIE);
        if (sessionId != null) {
            Optional<SessionRecord> session = sessionService.find(sessionId);
            if (session.isPresent()) {
                SessionRecord s = session.get();
                log.debug("authenticated via session session={}", Masking.mask(sessionId));
                return new AuthContext(s.username(), s.roles(), "session", Masking.mask(sessionId));
            }
            log.info("session credential rejected (revoked/expired) session={}", Masking.mask(sessionId));
        }
        String bearer = readBearer(request);
        if (bearer != null) {
            Optional<TokenService.TokenSubject> subject = tokenService.verifyAccessToken(bearer);
            if (subject.isPresent()) {
                TokenService.TokenSubject t = subject.get();
                log.debug("authenticated via token token={}", Masking.mask(bearer));
                return new AuthContext(t.username(), t.roles(), "token", Masking.mask(bearer));
            }
            log.info("bearer credential rejected (revoked/expired/forged) token={}", Masking.mask(bearer));
        }
        return null;
    }

    private void writeDenial(HttpServletResponse response, AccessDecision.DenyReason reason, String correlationId)
            throws IOException {
        int status = reason == AccessDecision.DenyReason.UNAUTHENTICATED ? 401 : 403;
        ApiError error = new ApiError(reason.name(),
                reason == AccessDecision.DenyReason.UNAUTHENTICATED
                        ? "authentication required" : "access denied",
                correlationId);
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
