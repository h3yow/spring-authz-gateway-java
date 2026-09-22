package com.github.h3yow.springauthzgatewayjava.auth;

import java.util.Set;

/**
 * 账号实体：口令仅以散列形式保存。
 */
public record AuthUser(
        String username,
        String passwordHash,
        Set<String> roles,
        boolean enabled,
        boolean credentialsExpired) {
}
