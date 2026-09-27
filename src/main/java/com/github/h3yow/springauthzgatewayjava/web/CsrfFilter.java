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
 * CSRF 防护：仅对"基于会话 Cookie 认证的改变状态请求"强制校验。
 *
 * <p>会话创建时下发一次性 CSRF 令牌（{@code X-CSRF-Token} 响应头），
 * 后续 POST/PUT/DELETE/PATCH 请求必须在同名请求头中回传，常量时间比较。
 * Bearer 令牌不依赖 Cookie，天然免疫 CSRF，予以豁免；安全方法（GET 等）与预检放行。
 * 已失效（撤销/过期）的会话 Cookie 不触发校验——旧凭据不得拖累
 * 仍然有效的 Bearer 凭据或公开入口（如重新登录、刷新令牌）。
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
        Optional<SessionRecord> session = sessionService.find(sessionId);
        if (session.isEmpty()) {
            // 未携带会话 Cookie，或 Cookie 已失效（撤销/过期）：
            // 失效旧凭据不得拖累 Bearer 请求或公开入口，CSRF 校验不适用
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
