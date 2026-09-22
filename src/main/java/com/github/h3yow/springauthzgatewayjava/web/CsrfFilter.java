package com.github.h3yow.springauthzgatewayjava.web;

import com.github.h3yow.springauthzgatewayjava.auth.session.SessionService;
import com.github.h3yow.springauthzgatewayjava.config.AuthSecurityProperties;
import com.github.h3yow.springauthzgatewayjava.util.Masking;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * CSRF 防护（同步器令牌模式）：
 * 仅对“会话认证 + 改状态方法”的请求强制校验 X-CSRF-Token 与会话绑定令牌一致；
 * Bearer 令牌认证不受 CSRF 影响（浏览器不会自动附带 Authorization 头）。
 */
public class CsrfFilter extends OncePerRequestFilter {

    public static final String HEADER = "X-CSRF-Token";

    private static final Logger log = LoggerFactory.getLogger(CsrfFilter.class);
    private static final Set<String> SAFE_METHODS = Set.of("GET", "HEAD", "OPTIONS");

    private final SessionService sessionService;
    private final AuthSecurityProperties props;

    public CsrfFilter(SessionService sessionService, AuthSecurityProperties props) {
        this.sessionService = sessionService;
        this.props = props;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        if (!props.isCsrfEnabled() || SAFE_METHODS.contains(request.getMethod())) {
            chain.doFilter(request, response);
            return;
        }
        AuthContext ctx = AuthContext.from(request);
        if (ctx == null || !"session".equals(ctx.credentialKind())) {
            chain.doFilter(request, response);
            return;
        }
        String sessionId = ctx.credentialId();
        String expected = sessionService.resolve(sessionId)
                .map(com.github.h3yow.springauthzgatewayjava.auth.session.SessionRecord::csrfToken)
                .orElse(null);
        String provided = request.getHeader(HEADER);
        if (expected == null || provided == null || !constantTimeEquals(expected, provided)) {
            log.info("csrf rejected path={} session={} provided={}",
                    request.getRequestURI(), Masking.prefix(sessionId), Masking.prefix(provided));
            // 过滤器内异常不会被 @RestControllerAdvice 捕获，直接写出错误响应
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("application/json");
            String cid = CorrelationIdFilter.currentId(request);
            response.getWriter().write(
                    "{\"code\":\"CSRF_TOKEN_INVALID\","
                            + "\"message\":\"state-changing request rejected: invalid CSRF token\","
                            + "\"correlationId\":\"" + cid + "\"}");
            return;
        }
        chain.doFilter(request, response);
    }

    private boolean constantTimeEquals(String a, String b) {
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }
}
