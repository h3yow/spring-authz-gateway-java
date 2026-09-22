package com.github.h3yow.springauthzgatewayjava.auth;

import java.time.Instant;
import java.util.Set;

/** 有状态会话记录（不可变，撤销即删除，避免半更新状态）。 */
public record SessionRecord(
        String sessionId,
        String username,
        Set<Role> roles,
        String csrfToken,
        Instant createdAt,
        Instant expiresAt) {

    public boolean expired(Instant now) {
        return now.isAfter(expiresAt);
    }
}
