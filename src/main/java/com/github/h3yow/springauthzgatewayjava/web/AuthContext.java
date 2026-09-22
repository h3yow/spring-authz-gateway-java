package com.github.h3yow.springauthzgatewayjava.web;

import com.github.h3yow.springauthzgatewayjava.auth.Role;
import java.util.Set;

/** 当前请求的认证主体（由过滤器写入请求属性）。 */
public record AuthContext(String username, Set<Role> roles, String credentialKind, String credentialId) {

    public static final String REQUEST_ATTRIBUTE = AuthContext.class.getName();
}
