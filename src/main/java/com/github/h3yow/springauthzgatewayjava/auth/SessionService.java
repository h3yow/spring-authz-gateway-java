package com.github.h3yow.springauthzgatewayjava.auth;

import com.github.h3yow.springauthzgatewayjava.util.Masking;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * 会话签发与撤销。
 * 会话记录不可变，撤销即从注册表原子删除，立即生效；
 * 不存在"半更新"中间态，过期会话在读取时惰性剔除。
 */
@Component
public class SessionService {

    private static final Logger log = LoggerFactory.getLogger(SessionService.class);
    private static final SecureRandom RANDOM = new SecureRandom();

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
        Instant now = clock.instant();
        SessionRecord record = new SessionRecord(
                newToken(), username, Set.copyOf(roles), newToken(),
                now, now.plus(properties.getSessionTtl()));
        sessions.put(record.sessionId(), record);
        log.info("session created user={} session={}", username, Masking.mask(record.sessionId()));
        return record;
    }

    /** 查询有效会话；不存在、已撤销或已过期一律返回空。 */
    public Optional<SessionRecord> find(String sessionId) {
        if (sessionId == null) {
            return Optional.empty();
        }
        SessionRecord record = sessions.get(sessionId);
        if (record == null) {
            return Optional.empty();
        }
        if (record.expired(clock.instant())) {
            sessions.remove(sessionId, record); // 惰性剔除过期会话
            return Optional.empty();
        }
        return Optional.of(record);
    }

    /** 撤销单个会话，立即生效；重复撤销是幂等 no-op。 */
    public void revoke(String sessionId) {
        if (sessionId != null && sessions.remove(sessionId) != null) {
            log.info("session revoked session={}", Masking.mask(sessionId));
        }
    }

    /** 撤销某用户的全部会话（如登出所有设备、口令变更）。 */
    public void revokeAllForUser(String username) {
        sessions.values().removeIf(s -> s.username().equals(username));
        log.info("all sessions revoked user={}", username);
    }

    private static String newToken() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
