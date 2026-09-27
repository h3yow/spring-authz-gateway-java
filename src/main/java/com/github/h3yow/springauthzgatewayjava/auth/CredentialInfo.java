package com.github.h3yow.springauthzgatewayjava.auth;

import java.time.Instant;

/**
 * 活跃凭据的自助管理视图（仅含元数据，绝不含任何凭据原文）。
 *
 * @param id         对外可引用的凭据标识（会话为独立随机句柄，令牌为 jti，均无法还原原文）
 * @param kind       凭据种类
 * @param clientKey  签发来源（如客户端 IP / 来源标识），用于分辨"哪个客户端"
 * @param issuedAt   签发时间
 * @param lastUsedAt 最近一次被服务端接受使用的时间（刚签发时尚未使用则为签发时间）
 * @param expiresAt  失效时间
 */
public record CredentialInfo(
        String id,
        CredentialKind kind,
        String clientKey,
        Instant issuedAt,
        Instant lastUsedAt,
        Instant expiresAt) {
}
