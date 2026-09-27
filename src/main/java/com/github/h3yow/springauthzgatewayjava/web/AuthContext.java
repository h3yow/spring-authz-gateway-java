package com.github.h3yow.springauthzgatewayjava.web;

import com.github.h3yow.springauthzgatewayjava.auth.CredentialKind;
import com.github.h3yow.springauthzgatewayjava.auth.Role;
import java.util.Set;

/**
 * 当前请求的认证主体（由过滤器写入请求属性）。
 *
 * @param kind          命中的凭据种类
 * @param displayId     脱敏后的凭据标识（仅用于日志/响应排查）
 * @param credentialRef 对外凭据管理句柄（会话为独立随机句柄，令牌为 jti；均非凭据原文）
 */
public record AuthContext(
        String username,
        Set<Role> roles,
        CredentialKind kind,
        String displayId,
        String credentialRef) {

    public static final String REQUEST_ATTRIBUTE = AuthContext.class.getName();
}
