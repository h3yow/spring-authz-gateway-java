package com.github.h3yow.springauthzgatewayjava.auth;

import com.github.h3yow.springauthzgatewayjava.util.Masking;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * 会话签发、滑动续期与撤销。
 *
 * <p>会话记录不可变。撤销即从注册表原子删除，立即生效；续期在同一个
 * {@code compute} 内完成"判定 + 续期"，撤销与续期竞争时以撤销为准——
 * 已删除的会话不会被续期"复活"，过期会话也不会因续期重新可用。
 *
 * <p>拒绝原因稳定：过期会话不会在判定后立即从注册表删除（否则下一次请求会
 * 漂移成"已撤销/未知"），而是作为过期墓碑保留，使同一凭据的重复请求始终
 * 得到 EXPIRED。墓碑在 {@code absoluteExpiresAt + auth.revocation-retention}
 * 之后惰性清除（有界内存）；显式撤销会移除墓碑，撤销优先于过期语义。
 *
 * <p>滑动续期语义：每次使用刷新 {@code lastUsedAt}；当剩余有效期不足
 * 空闲阈值（{@code auth.session-ttl}）的一半时，{@code expiresAt} 顺延为
 * {@code now + sessionTtl}，但永不超过绝对上限
 * {@code absoluteExpiresAt = createdAt + auth.session-max-lifetime}。
 */
@Component
public class SessionService {

    private static final Logger log = LoggerFactory.getLogger(SessionService.class);
    private static final SecureRandom RANDOM = new SecureRandom();

    /** 会话判定结果：有效 / 已过期 / 未知或已撤销（二者对外不可区分）。 */
    public enum SessionStatus { VALID, EXPIRED, UNKNOWN }

    /** 判定结果快照：状态 + 有效时的记录。 */
    public record Evaluation(SessionStatus status, SessionRecord record) {}

    /** 续期结果：当前记录 + 本次是否真正顺延了过期时间。 */
    public record TouchResult(SessionRecord record, boolean renewed) {}

    /**
     * 原子认证结果：状态 + 有效时的续期结果。
     * 判定与续期在同一个原子操作内完成，二者之间不存在被并发撤销的窗口。
     */
    public record SessionAuthResult(SessionStatus status, TouchResult touch) {}

    private final AuthProperties properties;
    private final Clock clock;
    private final ConcurrentHashMap<String, SessionRecord> sessions = new ConcurrentHashMap<>();

    @org.springframework.beans.factory.annotation.Autowired
    public SessionService(AuthProperties properties) {
        this(properties, Clock.systemUTC());
    }

    SessionService(AuthProperties properties, Clock clock) {
        this.properties = properties;
        this.clock = clock;
    }

    public SessionRecord create(String username, Set<Role> roles) {
        return create(username, roles, "unknown");
    }

    public SessionRecord create(String username, Set<Role> roles, String client) {
        Instant now = clock.instant();
        SessionRecord record = new SessionRecord(
                newToken(), newToken(), username, Set.copyOf(roles), newToken(),
                client == null ? "unknown" : client,
                now, now, now.plus(properties.getSessionTtl()),
                now.plus(properties.getSessionMaxLifetime()));
        sessions.put(record.sessionId(), record);
        log.info("session created user={} session={} credential={}", username,
                Masking.mask(record.sessionId()), Masking.mask(record.credentialId()));
        return record;
    }

    /** 查询有效会话；不存在、已撤销或已过期一律返回空。 */
    public Optional<SessionRecord> find(String sessionId) {
        Evaluation evaluation = evaluate(sessionId);
        return evaluation.status() == SessionStatus.VALID
                ? Optional.of(evaluation.record()) : Optional.empty();
    }

    /** 区分"有效 / 已过期 / 未知或已撤销"的判定，供认证过滤器给出可区分的拒绝原因。 */
    public Evaluation evaluate(String sessionId) {
        if (sessionId == null) {
            return new Evaluation(SessionStatus.UNKNOWN, null);
        }
        SessionRecord record = sessions.get(sessionId);
        if (record == null) {
            return new Evaluation(SessionStatus.UNKNOWN, null);
        }
        Instant now = clock.instant();
        if (!record.expired(now)) {
            return new Evaluation(SessionStatus.VALID, record);
        }
        // 过期墓碑：保留期内稳定返回 EXPIRED，不做惰性删除；超过保留期才清除
        if (tombstoneExpired(record, now)) {
            sessions.remove(sessionId, record);
            return new Evaluation(SessionStatus.UNKNOWN, null);
        }
        return new Evaluation(SessionStatus.EXPIRED, null);
    }

    /**
     * 原子的"判定 + 滑动续期"：认证过滤器的唯一入口。
     * 有效会话在同一个 compute 内完成续期；过期会话作为墓碑保留并稳定返回
     * EXPIRED；已撤销（不存在）返回 UNKNOWN。不存在判定与续期之间被并发撤销
     * 的窗口。
     */
    public SessionAuthResult authenticate(String sessionId) {
        if (sessionId == null) {
            return new SessionAuthResult(SessionStatus.UNKNOWN, null);
        }
        Instant now = clock.instant();
        SessionAuthResult[] result = new SessionAuthResult[1];
        sessions.computeIfPresent(sessionId, (id, current) -> {
            if (current.expired(now)) {
                if (tombstoneExpired(current, now)) {
                    return null; // 墓碑超过保留期，清除
                }
                result[0] = new SessionAuthResult(SessionStatus.EXPIRED, null);
                return current; // 保留过期墓碑，绝不复活
            }
            TouchResult touched = renew(current, now);
            result[0] = new SessionAuthResult(SessionStatus.VALID, touched);
            return touched.record();
        });
        return result[0] != null ? result[0] : new SessionAuthResult(SessionStatus.UNKNOWN, null);
    }

    /**
     * 滑动续期：原子地更新最近使用时间，并在剩余有效期过半后顺延过期时间
     * （不超过绝对上限）。已撤销或已过期的会话不会被续期复活。
     *
     * @return 会话仍存在且有效时返回续期结果，否则返回空
     */
    public Optional<TouchResult> touch(String sessionId) {
        if (sessionId == null) {
            return Optional.empty();
        }
        Instant now = clock.instant();
        TouchResult[] result = new TouchResult[1];
        sessions.computeIfPresent(sessionId, (id, current) -> {
            if (current.expired(now)) {
                if (tombstoneExpired(current, now)) {
                    return null;
                }
                return current; // 过期墓碑保留，不复活
            }
            result[0] = renew(current, now);
            return result[0].record();
        });
        return Optional.ofNullable(result[0]);
    }

    /** 计算续期后的新记录（纯函数，调用方须在原子块内）。 */
    private TouchResult renew(SessionRecord current, Instant now) {
        boolean renewable = current.expiresAt().isBefore(current.absoluteExpiresAt())
                && now.plus(properties.getSessionTtl().dividedBy(2)).isAfter(current.expiresAt());
        Instant newExpiry = renewable
                ? min(now.plus(properties.getSessionTtl()), current.absoluteExpiresAt())
                : current.expiresAt();
        boolean renewed = newExpiry.isAfter(current.expiresAt());
        return new TouchResult(new SessionRecord(
                current.sessionId(), current.credentialId(), current.username(),
                current.roles(), current.csrfToken(), current.client(),
                current.createdAt(), now, newExpiry, current.absoluteExpiresAt()), renewed);
    }

    /** 撤销单个会话，立即生效；重复撤销是幂等 no-op（过期墓碑同样可被显式撤销移除）。 */
    public void revoke(String sessionId) {
        if (sessionId != null && sessions.remove(sessionId) != null) {
            log.info("session revoked session={}", Masking.mask(sessionId));
        }
    }

    /** 按公开凭据标识撤销：仅当凭据属于该用户时生效，返回是否命中（含过期墓碑）。 */
    public boolean revokeByCredentialId(String username, String credentialId) {
        if (credentialId == null) {
            return false;
        }
        for (SessionRecord s : sessions.values()) {
            if (s.credentialId().equals(credentialId) && s.username().equals(username)) {
                sessions.remove(s.sessionId(), s);
                log.info("session revoked by credential user={} credential={}",
                        username, Masking.mask(credentialId));
                return true;
            }
        }
        return false;
    }

    /** 撤销某用户的全部会话（如登出所有设备、口令变更），含过期墓碑。 */
    public void revokeAllForUser(String username) {
        sessions.values().removeIf(s -> s.username().equals(username));
        log.info("all sessions revoked user={}", username);
    }

    /** 撤销某用户除指定会话外的全部会话（"撤销其他全部凭据"）。 */
    public void revokeAllForUserExcept(String username, String keepSessionId) {
        sessions.values().removeIf(s -> s.username().equals(username)
                && !s.sessionId().equals(keepSessionId));
        log.info("other sessions revoked user={} keep={}", username, Masking.mask(keepSessionId));
    }

    /** 列出某用户当前仍有效的会话（过期墓碑不展示，超过保留期顺带清除）。 */
    public List<SessionRecord> listForUser(String username) {
        Instant now = clock.instant();
        return sessions.values().stream()
                .filter(s -> s.username().equals(username))
                .filter(s -> {
                    if (s.expired(now)) {
                        if (tombstoneExpired(s, now)) {
                            sessions.remove(s.sessionId(), s);
                        }
                        return false;
                    }
                    return true;
                })
                .toList();
    }

    /** 墓碑是否已超过保留期（绝对上限之后再保留 revocation-retention）。 */
    private boolean tombstoneExpired(SessionRecord record, Instant now) {
        return now.isAfter(record.absoluteExpiresAt().plus(properties.getRevocationRetention()));
    }

    private static Instant min(Instant a, Instant b) {
        return a.isBefore(b) ? a : b;
    }

    private static String newToken() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
