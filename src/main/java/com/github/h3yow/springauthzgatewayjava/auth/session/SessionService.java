package com.github.h3yow.springauthzgatewayjava.auth.session;

import com.github.h3yow.springauthzgatewayjava.config.AuthSecurityProperties;
import com.github.h3yow.springauthzgatewayjava.util.Masking;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * 内存会话存储：创建、解析、注销。
 * 注销即物理删除，任何入口再次使用该会话标识都会立即失败。
 */
@Service
public class SessionService {

    private static final Logger log = LoggerFactory.getLogger(SessionService.class);

    private final ConcurrentHashMap<String, SessionRecord> sessions = new ConcurrentHashMap<>();
    private final SecureRandom random = new SecureRandom();
    private final AuthSecurityProperties props;
    private final Clock clock;

    public SessionService(AuthSecurityProperties props, Clock clock) {
        this.props = props;
        this.clock = clock;
    }

    public SessionRecord create(String username) {
        SessionRecord record = new SessionRecord(
                newId(), username, newId(), Instant.now(clock).plus(props.getSessionTtl()));
        sessions.put(record.sessionId(), record);
        log.info("session created user={} session={}", username, Masking.prefix(record.sessionId()));
        return record;
    }

    /** 解析会话：不存在或已过期均返回空；过期会话顺带清除。 */
    public Optional<SessionRecord> resolve(String sessionId) {
        if (sessionId == null) {
            return Optional.empty();
        }
        SessionRecord record = sessions.get(sessionId);
        if (record == null) {
            return Optional.empty();
        }
        if (record.isExpired(Instant.now(clock))) {
            sessions.remove(sessionId, record);
            log.info("session expired and evicted session={}", Masking.prefix(sessionId));
            return Optional.empty();
        }
        return Optional.of(record);
    }

    public void invalidate(String sessionId) {
        if (sessionId != null && sessions.remove(sessionId) != null) {
            log.info("session invalidated session={}", Masking.prefix(sessionId));
        }
    }

    public void invalidateAllForUser(String username) {
        sessions.values().removeIf(r -> r.username().equals(username));
        log.info("all sessions invalidated user={}", username);
    }

    private String newId() {
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
