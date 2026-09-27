package com.github.h3yow.springauthzgatewayjava.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.h3yow.springauthzgatewayjava.auth.SessionRecord;
import com.github.h3yow.springauthzgatewayjava.auth.SessionService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * CSRF 防护：仅对"基于<strong>当前有效</strong>会话 Cookie 认证的改变状态请求"强制校验。
 *
 * <p>会话创建时下发一次性 CSRF 令牌（{@code X-CSRF-Token} 响应头），
 * 后续 POST/PUT/DELETE/PATCH 请求必须在同名请求头中回传，常量时间比较。
 *
 * <p>豁免规则（避免失效旧凭据拖累正常入口）：
 * <ul>
 *   <li>安全方法（GET/HEAD/OPTIONS/TRACE）与预检放行；</li>
 *   <li>未携带会话 Cookie 的请求（纯 Bearer）天然免疫 CSRF，放行；</li>
 *   <li>携带的会话 Cookie 已撤销/过期/不被认可时，视为"没有有效会话凭据"而放行——
 *       此时请求要么匿名访问公开入口（登录/刷新不应被旧 Cookie 拖累），
 *       要么由认证过滤器以有效 Bearer 通过，要么被认证过滤器拒绝。</li>
 * </ul>
 */
public class CsrfFilter extends OncePerRequestFilter {

    public static final String CSRF_HEADER = "X-CSRF-Token";

    private static final Logger log = LoggerFactory.getLogger(CsrfFilter.class);

    private final SessionService sessionService;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public CsrfFilter(SessionService sessionService) {
        this.sessionService = sessionService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        if (isSafeMethod(request.getMethod())) {
            chain.doFilter(request, response);
            return;
        }
        String sessionId = readCookie(request, AuthFilter.SESSION_COOKIE);
        if (sessionId == null) {
            chain.doFilter(request, response);
            return;
        }
        // 只读查询有效会话：失效的旧 Cookie 不触发 CSRF 拦截，避免拖累登录/刷新/Bearer 请求
        Optional<SessionRecord> session = sessionService.peek(sessionId);
        if (session.isEmpty()) {
            chain.doFilter(request, response);
            return;
        }
        String presented = request.getHeader(CSRF_HEADER);
        boolean valid = presented != null && MessageDigest.isEqual(
                session.get().csrfToken().getBytes(StandardCharsets.UTF_8),
                presented.getBytes(StandardCharsets.UTF_8));
        if (!valid) {
            String correlationId = correlationId(request);
            log.info("csrf rejected correlation={} path={}", correlationId, request.getRequestURI());
            response.setStatus(403);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.getWriter().write(objectMapper.writeValueAsString(
                    new ApiError("CSRF_TOKEN_INVALID", "csrf token missing or mismatched", correlationId)));
            return;
        }
        chain.doFilter(request, response);
    }

    private static boolean isSafeMethod(String method) {
        return "GET".equals(method) || "HEAD".equals(method) || "OPTIONS".equals(method) || "TRACE".equals(method);
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

    private static String correlationId(HttpServletRequest request) {
        Object id = request.getAttribute(AuthFilter.CORRELATION_ATTRIBUTE);
        return id != null ? id.toString() : UUID.randomUUID().toString();
    }
}
