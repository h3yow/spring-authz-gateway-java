package com.github.h3yow.springauthzgatewayjava.web;

import com.github.h3yow.springauthzgatewayjava.auth.AuthUser;
import jakarta.servlet.http.HttpServletRequest;

/**
 * 一次请求的认证上下文：来源（会话或令牌）+ 账号。
 */
public record AuthContext(AuthUser user, String credentialKind, String credentialId) {

    public static final String REQUEST_ATTRIBUTE = AuthContext.class.getName() + ".ATTR";

    /** 从请求属性中取出认证上下文，未认证时返回 null。 */
    public static AuthContext from(HttpServletRequest request) {
        Object ctx = request.getAttribute(REQUEST_ATTRIBUTE);
        return ctx instanceof AuthContext authContext ? authContext : null;
    }
}
