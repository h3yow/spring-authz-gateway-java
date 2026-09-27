package com.github.h3yow.springauthzgatewayjava.auth;

import com.github.h3yow.springauthzgatewayjava.util.Masking;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * 会话签发、滑动续期与撤销。
 *
 * <p>存储为 {@link ConcurrentHashMap}，键为会话内部标识（Cookie 值）；
 * 另维护"对外凭据句柄 -> 内部标识"索引，供自助管理引用。
 *
 * <p>并发正确性（续期与撤销竞争时撤销为准）：所有状态迁移都在
 * {@link ConcurrentHashMap#compute} 内基于"当前值"原子决定新值——
 * 墓碑（{@code revoked=true}）与不存在条目在任何迁移中都不会被重新激活，
 * 因此续期不可能把已撤销/已过期会话救活，重复撤销幂等。
 */
@Component
public class SessionService {

    private static final Logger log = LoggerFactory.getLogger(SessionService.class);
    private static final SecureRandom RANDOM = new SecureRandom();

    private final AuthProperties properties;
    private final Clock clock;
    private final ConcurrentHashMap<String, SessionRecord> sessions = new ConcurrentHashMap<>();
    /** 对外凭据句柄 -> 会话内部标识。 */
    private final ConcurrentHashMap<String, String> byCredentialId = new ConcurrentHashMap<>();

    @org.springframework.beans.factory.annotation.Autowired
    public SessionService(AuthProperties properties) {
        this(properties, Clock.systemUTC());
    }

    /** 测试/嵌入用：可注入时钟。 */
    public SessionService(AuthProperties properties, Clock clock) {
        this.properties = properties;
        this.clock = clock;
    }

    /** 兼容入口：未提供客户端来源时以 unknown 签发。 */
    public SessionRecord create(String username, Set<Role> roles) {
        return create(username, roles, "unknown");
    }

    public SessionRecord create(String username, Set<Role> roles, String clientKey) {
        Instant now = clock.instant();
        Instant idleExpiry = now.plus(idleTtl());
        Instant absoluteExpiry = now.plus(maxTtl());
        SessionRecord record = new SessionRecord(
                newToken(), newToken(), username, Set.copyOf(roles), newToken(),
                clientKey == null ? "unknown" : clientKey,
                now, now, idleExpiry, absoluteExpiry, false);
        sessions.put(record.sessionId(), record);
        byCredentialId.put(record.credentialId(), record.sessionId());
        log.info("session created user={} session={} client={}",
                username, Masking.mask(record.sessionId()), record.clientKey());
        return record;
    }

    /**
     * 查询会话并视为一次有效使用：原子完成"空闲滑动续期 + 失效校验"。
     * 已撤销（墓碑）、已过期、不存在均返回空，且不会被续期救活。
     */
    public Optional<SessionRecord> find(String sessionId) {
        if (sessionId == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(sessions.computeIfPresent(sessionId, (id, cur) -> {
            if (cur.revoked()) {
                return cur; // 墓碑保留
            }
            if (cur.expired(clock.instant())) {
                return cur; // 过期记录保留，使 stateOf 能稳定区分 EXPIRED（读取方按 expired 拒绝）
            }
            // 空闲滑动：以当前时间为基准顺延，绝对上限由 expiresAt 截断保证
            return cur.touch(clock.instant(), clock.instant().plus(idleTtl()));
        })).filter(r -> !r.revoked() && !r.expired(clock.instant()));
    }

    /** 只读查询：不触发滑动（用于 CSRF 校验等不代表"资源使用"的场合）。 */
    public Optional<SessionRecord> peek(String sessionId) {
        if (sessionId == null) {
            return Optional.empty();
        }
        SessionRecord record = sessions.get(sessionId);
        if (record == null || record.revoked() || record.expired(clock.instant())) {
            return Optional.empty();
        }
        return Optional.of(record);
    }

    /** 按对外凭据句柄查询会话（不触发滑动）。 */
    public Optional<SessionRecord> findByCredentialId(String credentialId) {
        if (credentialId == null) {
            return Optional.empty();
        }
        String id = byCredentialId.get(credentialId);
        return id == null ? Optional.empty() : peek(id);
    }

    /** 判定会话的生命周期状态，稳定区分 已撤销 / 已过期 / 不被认可。 */
    public CredentialState stateOf(String sessionId) {
        if (sessionId == null) {
            return CredentialState.UNKNOWN;
        }
        SessionRecord record = sessions.get(sessionId);
        if (record == null) {
            return CredentialState.UNKNOWN;
        }
        if (record.revoked()) {
            return CredentialState.REVOKED;
        }
        if (record.expired(clock.instant())) {
            return CredentialState.EXPIRED;
        }
        return CredentialState.VALID;
    }

    /** 撤销单个会话，立即生效；对墓碑/不存在条目是幂等 no-op，绝不重新激活。 */
    public boolean revoke(String sessionId) {
        if (sessionId == null) {
            return false;
        }
        final boolean[] changed = {false};
        sessions.computeIfPresent(sessionId, (id, cur) -> {
            if (!cur.revoked() && !cur.expired(clock.instant())) {
                changed[0] = true;
                log.info("session revoked session={}", Masking.mask(sessionId));
                return cur.asRevoked();
            }
            return cur; // 已撤销/已过期：幂等 no-op，过期不翻成撤销墓碑
        });
        return changed[0];
    }

    /**
     * 撤销某用户的全部会话（如登出所有设备、口令变更）。
     * @return 被撤销的（此前有效的）会话数量
     */
    public int revokeAllForUser(String username) {
        return revokeForUserExcept(username, null);
    }

    /**
     * 撤销某用户除指定会话（内部标识）之外的全部会话。
     * 墓碑不会被复活，重复调用幂等。
     *
     * @return 被撤销的（此前有效的）会话数量
     */
    public int revokeForUserExcept(String username, String keepSessionId) {
        final int[] changed = {0};
        for (Map.Entry<String, SessionRecord> e : sessions.entrySet()) {
            SessionRecord cur = e.getValue();
            if (!cur.username().equals(username) || cur.sessionId().equals(keepSessionId)) {
                continue;
            }
            sessions.compute(e.getKey(), (id, existing) -> {
                if (existing == null || existing.revoked() || existing.expired(clock.instant())) {
                    return existing; // 过期凭据不计入撤销数，保持 EXPIRED 判定
                }
                changed[0]++;
                return existing.asRevoked();
            });
        }
        log.info("sessions revoked user={} keep={} count={}", username,
                Masking.mask(keepSessionId), changed[0]);
        return changed[0];
    }

    /** 用户名下当前仍然有效的会话视图（仅元数据）。 */
    public List<CredentialInfo> activeInfos(String username) {
        Instant now = clock.instant();
        List<CredentialInfo> result = new ArrayList<>();
        for (SessionRecord r : sessions.values()) {
            if (r.username().equals(username) && !r.revoked() && !r.expired(now)) {
                result.add(new CredentialInfo(r.credentialId(), CredentialKind.SESSION,
                        r.clientKey(), r.issuedAt(), r.lastUsedAt(), r.expiresAt()));
            }
        }
        return result;
    }

    private java.time.Duration idleTtl() {
        return properties.getSessionIdleTtl() != null
                ? properties.getSessionIdleTtl() : properties.getSessionTtl();
    }

    private java.time.Duration maxTtl() {
        return properties.getSessionMaxTtl() != null
                ? properties.getSessionMaxTtl() : idleTtl();
    }

    private static String newToken() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
