package com.github.h3yow.springauthzgatewayjava.web;

import com.github.h3yow.springauthzgatewayjava.auth.AuthUser;
import com.github.h3yow.springauthzgatewayjava.auth.UserStore;
import com.github.h3yow.springauthzgatewayjava.auth.session.SessionService;
import com.github.h3yow.springauthzgatewayjava.auth.token.TokenService;
import com.github.h3yow.springauthzgatewayjava.util.Masking;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * 解析认证凭据：优先 Bearer 令牌，其次会话 Cookie。
 * 已注销/撤销/过期的凭据在此即被丢弃，请求以匿名身份继续，
 * 由授权拦截器按缺省拒绝策略处理。停用账号的凭据同样不被接受。
 */
public class AuthFilter extends OncePerRequestFilter {

    public static final String SESSION_COOKIE = "SESSION";

    private static final Logger log = LoggerFactory.getLogger(AuthFilter.class);

    private final SessionService sessionService;
    private final TokenService tokenService;
    private final UserStore userStore;

    public AuthFilter(SessionService sessionService, TokenService tokenService, UserStore userStore) {
        this.sessionService = sessionService;
        this.tokenService = tokenService;
        this.userStore = userStore;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        resolveToken(request).or(() -> resolveSession(request))
                .ifPresent(ctx -> request.setAttribute(AuthContext.REQUEST_ATTRIBUTE, ctx));
        chain.doFilter(request, response);
    }

    private Optional<AuthContext> resolveToken(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        if (header == null || !header.startsWith("Bearer ")) {
            return Optional.empty();
        }
        String token = header.substring(7);
        return tokenService.validate(token)
                .flatMap(vt -> activeUser(vt.username())
                        .map(user -> {
                            log.debug("authenticated via token user={} jti={}", user.username(), vt.jti());
                            return new AuthContext(user, "token", vt.jti());
                        }));
    }

    private Optional<AuthContext> resolveSession(HttpServletRequest request) {
        String sessionId = readCookie(request, SESSION_COOKIE);
        if (sessionId == null) {
            return Optional.empty();
        }
        return sessionService.resolve(sessionId)
                .flatMap(session -> activeUser(session.username())
                        .map(user -> {
                            log.debug("authenticated via session user={} session={}",
                                    user.username(), Masking.prefix(sessionId));
                            return new AuthContext(user, "session", sessionId);
                        }));
    }

    /** 停用账号的既有凭据一律不再接受。 */
    private Optional<AuthUser> activeUser(String username) {
        return userStore.findByUsername(username).filter(AuthUser::enabled);
    }

    private String readCookie(HttpServletRequest request, String name) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return null;
        }
        for (Cookie cookie : cookies) {
            if (name.equals(cookie.getName())) {
                return cookie.getValue();
            }
        }
        return null;
    }
}
