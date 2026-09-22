package com.github.h3yow.springauthzgatewayjava.auth.session;

import java.time.Instant;

/**
 * 有状态会话记录。
 */
public record SessionRecord(String sessionId, String username, String csrfToken, Instant expiresAt) {

    public boolean isExpired(Instant now) {
        return !expiresAt.isAfter(now);
    }
}
