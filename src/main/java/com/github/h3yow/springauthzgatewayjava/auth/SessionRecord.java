package com.github.h3yow.springauthzgatewayjava.auth;

import java.time.Instant;
import java.util.Set;

/**
 * 有状态会话记录。
 *
 * <p>字段承载滑动会话语义：{@code lastUsedAt} 随每次有效使用顺延（空闲判定基准），
 * {@code absoluteExpiresAt} 为自签发起不可突破的绝对上限。
 * 撤销标记（墓碑）与时间字段均为 final，状态迁移只能通过以新记录整体替换注册表条目完成，
 * 不存在"半更新"中间态。
 *
 * @param sessionId          会话内部标识（即 SESSION Cookie 值，不对外展示原文）
 * @param credentialId       对外暴露的凭据管理句柄（独立随机值，无法据此伪造 Cookie）
 * @param username           所属用户
 * @param roles              角色快照
 * @param csrfToken          CSRF 令牌
 * @param clientKey          签发来源（客户端 IP 等）
 * @param issuedAt           签发时间
 * @param lastUsedAt         最近一次被服务端接受使用的时间
 * @param idleExpiresAt      空闲失效时间（每次使用向后顺延）
 * @param absoluteExpiresAt  绝对失效时间（永不顺延）
 * @param revoked            是否已撤销（墓碑，使"已撤销"可与"不存在/已过期"稳定区分）
 */
public record SessionRecord(
        String sessionId,
        String credentialId,
        String username,
        Set<Role> roles,
        String csrfToken,
        String clientKey,
        Instant issuedAt,
        Instant lastUsedAt,
        Instant idleExpiresAt,
        Instant absoluteExpiresAt,
        boolean revoked) {

    /** 真实失效时间：空闲截止与绝对截止中较早者。 */
    public Instant expiresAt() {
        return idleExpiresAt.isBefore(absoluteExpiresAt) ? idleExpiresAt : absoluteExpiresAt;
    }

    public boolean expired(Instant now) {
        return !now.isBefore(expiresAt());
    }

    /** 以"最近使用时间 + 空闲 TTL"顺延，但绝不超过绝对上限。 */
    public SessionRecord touch(Instant now, Instant newIdleExpiresAt) {
        return new SessionRecord(sessionId, credentialId, username, roles, csrfToken, clientKey,
                issuedAt, now, newIdleExpiresAt, absoluteExpiresAt, revoked);
    }

    /** 生成撤销墓碑：保留身份与归属信息，仅翻转撤销标记。 */
    public SessionRecord asRevoked() {
        return new SessionRecord(sessionId, credentialId, username, roles, csrfToken, clientKey,
                issuedAt, lastUsedAt, idleExpiresAt, absoluteExpiresAt, true);
    }
}
