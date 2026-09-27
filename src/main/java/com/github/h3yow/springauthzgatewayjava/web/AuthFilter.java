package com.github.h3yow.springauthzgatewayjava.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.h3yow.springauthzgatewayjava.auth.CredentialKind;
import com.github.h3yow.springauthzgatewayjava.auth.CredentialState;
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
import java.time.Instant;
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
 * {@code Authorization: Bearer} 访问令牌。携带一种已失效的凭据不会拖累另一种有效凭据：
 * 只要任一凭据有效即认证通过；两种都无效时按"最坏情况"给出稳定可区分的判定结果。
 *
 * <p>受保护资源的未通过判定稳定区分：
 * <ul>
 *   <li>完全没有凭据 -> {@code CREDENTIAL_MISSING}；</li>
 *   <li>凭据曾存在但已撤销 -> {@code CREDENTIAL_REVOKED}；</li>
 *   <li>凭据已超过失效时间 -> {@code CREDENTIAL_EXPIRED}；</li>
 *   <li>服务端不认可（伪造/重启前旧凭据）-> {@code CREDENTIAL_INVALID}。</li>
 * </ul>
 * 优先级 撤销 &gt; 过期 &gt; 不认可；这些结果不暴露账号是否存在，也不含凭据原文。
 *
 * <p>会话每次有效使用触发滑动续期，续期结果经 {@code X-Session-Expires-At} 等响应头明确告知客户端，
 * 且无论如何滑动都不超过绝对上限。每个请求另分配 {@code X-Correlation-Id}。
 */
public class AuthFilter extends OncePerRequestFilter {

    public static final String CORRELATION_ATTRIBUTE = "correlationId";
    public static final String CORRELATION_HEADER = "X-Correlation-Id";
    public static final String SESSION_COOKIE = "SESSION";

    /** 会话滑动续期结果响应头：当前空闲截止、绝对上限、距空闲截止剩余秒数。 */
    public static final String SESSION_EXPIRES_AT_HEADER = "X-Session-Expires-At";
    public static final String SESSION_ABSOLUTE_EXPIRES_AT_HEADER = "X-Session-Absolute-Expires-At";
    public static final String SESSION_MAX_AGE_HEADER = "X-Session-Max-Age";

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

    /** 认证尝试结果：成功携带主体，失败携带可区分的凭据状态。 */
    private record Attempt(AuthContext context, CredentialState failure) {
        static Attempt success(AuthContext c) { return new Attempt(c, null); }
        static Attempt fail(CredentialState state) { return new Attempt(null, state); }
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String correlationId = UUID.randomUUID().toString();
        request.setAttribute(CORRELATION_ATTRIBUTE, correlationId);
        response.setHeader(CORRELATION_HEADER, correlationId);

        Attempt attempt = authenticate(request);
        AuthContext context = attempt.context();
        if (context != null) {
            request.setAttribute(AuthContext.REQUEST_ATTRIBUTE, context);
            if (context.kind() == CredentialKind.SESSION) {
                emitSlidingHeaders(request, response);
            }
        }

        boolean authenticated = context != null;
        Set<com.github.h3yow.springauthzgatewayjava.auth.Role> roles =
                authenticated ? context.roles() : Set.of();
        AccessDecision decision = accessPolicy.decide(
                request.getMethod(), request.getRequestURI(), roles, authenticated);
        if (!decision.permitted()) {
            log.info("request denied correlation={} path={} reason={}",
                    correlationId, request.getRequestURI(), decision.denyReason());
            writeDenial(response, decision.denyReason(), attempt.failure(), correlationId);
            return;
        }
        chain.doFilter(request, response);
    }

    /**
     * 依次尝试会话 Cookie 与 Bearer 令牌；任一有效即成功，且两种凭据互不拖累。
     * 两者都失败时取"最坏"状态（撤销 &gt; 过期 &gt; 不认可）；都未携带视为缺失。
     */
    private Attempt authenticate(HttpServletRequest request) {
        CredentialState worst = null;
        boolean presented = false;

        String sessionId = readCookie(request, SESSION_COOKIE);
        if (sessionId != null) {
            presented = true;
            Optional<SessionRecord> session = sessionService.find(sessionId); // find 原子完成滑动续期
            if (session.isPresent()) {
                SessionRecord s = session.get();
                log.debug("authenticated via session session={}", Masking.mask(sessionId));
                return Attempt.success(new AuthContext(s.username(), s.roles(),
                        CredentialKind.SESSION, Masking.mask(sessionId), s.credentialId()));
            }
            CredentialState state = sessionService.stateOf(sessionId);
            log.info("session credential rejected state={} session={}", state, Masking.mask(sessionId));
            worst = worse(worst, state);
        }

        String bearer = readBearer(request);
        if (bearer != null) {
            presented = true;
            Optional<TokenService.TokenSubject> subject = tokenService.verifyAccessToken(bearer);
            if (subject.isPresent()) {
                TokenService.TokenSubject t = subject.get();
                log.debug("authenticated via token token={}", Masking.mask(bearer));
                // jti 只用于归属判定，从令牌载荷之外无法获得；这里通过元数据反查会暴露原文风险，
                // 因此管理句柄由控制器在自助管理端点另行提供；过滤器仅记录脱敏标识。
                String jti = tokenService.jtiOf(bearer);
                return Attempt.success(new AuthContext(t.username(), t.roles(),
                        CredentialKind.ACCESS_TOKEN, Masking.mask(bearer), jti));
            }
            CredentialState state = tokenService.stateOfAccessToken(bearer);
            log.info("bearer credential rejected state={} token={}", state, Masking.mask(bearer));
            worst = worse(worst, state);
        }

        return presented ? Attempt.fail(worst) : Attempt.fail(null);
    }

    private void emitSlidingHeaders(HttpServletRequest request, HttpServletResponse response) {
        String sessionId = readCookie(request, SESSION_COOKIE);
        sessionService.peek(sessionId).ifPresent(s -> {
            Instant now = java.time.Instant.now();
            response.setHeader(SESSION_EXPIRES_AT_HEADER, s.expiresAt().toString());
            response.setHeader(SESSION_ABSOLUTE_EXPIRES_AT_HEADER, s.absoluteExpiresAt().toString());
            long maxAge = Math.max(0, s.expiresAt().getEpochSecond() - now.getEpochSecond());
            response.setHeader(SESSION_MAX_AGE_HEADER, String.valueOf(maxAge));
            // 顺延浏览器 Cookie 有效期（与新空闲截止一致），使客户端与服务端感知一致
            response.addHeader(HttpHeaders.SET_COOKIE,
                    SESSION_COOKIE + "=" + sessionId + "; Path=/; HttpOnly; SameSite=Strict; Max-Age="
                            + maxAge);
        });
    }

    /** 失效状态取最坏：REVOKED &gt; EXPIRED &gt; UNKNOWN。 */
    private static CredentialState worse(CredentialState a, CredentialState b) {
        if (a == null) {
            return b;
        }
        if (b == null) {
            return a;
        }
        return rank(a) >= rank(b) ? a : b;
    }

    private static int rank(CredentialState s) {
        return switch (s) {
            case REVOKED -> 3;
            case EXPIRED -> 2;
            case UNKNOWN -> 1;
            default -> 0;
        };
    }

    private void writeDenial(HttpServletResponse response, AccessDecision.DenyReason reason,
                             CredentialState credentialState, String correlationId)
            throws IOException {
        if (reason == AccessDecision.DenyReason.FORBIDDEN_ROLE
                || reason == AccessDecision.DenyReason.FORBIDDEN_RESOURCE) {
            writeError(response, 403, reason.name(), "access denied", correlationId);
            return;
        }
        // 未认证：按凭据生命周期状态给出稳定可区分的错误码
        String code;
        String message;
        if (credentialState == null) {
            code = "CREDENTIAL_MISSING";
            message = "authentication required";
        } else {
            code = switch (credentialState) {
                case REVOKED -> "CREDENTIAL_REVOKED";
                case EXPIRED -> "CREDENTIAL_EXPIRED";
                default -> "CREDENTIAL_INVALID";
            };
            message = "authentication required";
        }
        writeError(response, 401, code, message, correlationId);
    }

    private void writeError(HttpServletResponse response, int status, String code,
                            String message, String correlationId) throws IOException {
        response.setStatus(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write(objectMapper.writeValueAsString(new ApiError(code, message, correlationId)));
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
