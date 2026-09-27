package com.github.h3yow.springauthzgatewayjava.auth;

import java.time.Instant;
import java.util.Set;

/**
 * 有状态会话记录（不可变，撤销即删除，避免半更新状态）。
 *
 * <p>{@code sessionId} 是秘密凭据本体，绝不外泄；{@code credentialId} 是公开的
 * 管理标识，用于凭据自助管理（列举/撤销），与凭据本体分离。
 * 滑动续期通过原子替换产生新记录：{@code lastUsedAt} 每次使用更新，
 * {@code expiresAt}（空闲上限）顺延但永不超过 {@code absoluteExpiresAt}（绝对上限）。
 */
public record SessionRecord(
        String sessionId,
        String credentialId,
        String username,
        Set<Role> roles,
        String csrfToken,
        String client,
        Instant createdAt,
        Instant lastUsedAt,
        Instant expiresAt,
        Instant absoluteExpiresAt) {

    public boolean expired(Instant now) {
        return now.isAfter(expiresAt);
    }
}
