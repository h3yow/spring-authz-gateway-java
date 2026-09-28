package com.github.h3yow.springauthzgatewayjava.auth;

import static org.junit.jupiter.api.Assertions.*;

import java.time.Duration;
import java.time.Instant;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 同一会话凭据在生命周期内拒绝原因稳定：
 * 过期凭据重复判定始终 EXPIRED，不漂移为 UNKNOWN(已撤销)；
 * 显式撤销优先于过期——撤销后稳定 UNKNOWN；过期墓碑不会被续期复活。
 */
class SessionReasonStabilityTest {

    private static final Logger log = LoggerFactory.getLogger(SessionReasonStabilityTest.class);
    private static final Instant T0 = Instant.parse("2026-09-28T00:00:00Z");

    private AuthProperties props() {
        AuthProperties p = new AuthProperties();
        p.setSessionTtl(Duration.ofMinutes(30));
        p.setSessionMaxLifetime(Duration.ofHours(2));
        p.setRevocationRetention(Duration.ofHours(1));
        return p;
    }

    @Test
    void expiredSessionReasonIsStableAcrossRepeatedEvaluations() {
        LoginGuardTest.MutableClock clock = new LoginGuardTest.MutableClock(T0);
        SessionService sessions = new SessionService(props(), clock);
        SessionRecord s = sessions.create("alice", Set.of(Role.USER));
        clock.advance(Duration.ofMinutes(31)); // 空闲超时

        for (int i = 1; i <= 5; i++) {
            SessionService.SessionStatus status = sessions.evaluate(s.sessionId()).status();
            log.info("input: expired session evaluation #{} -> {}", i, status);
            assertEquals(SessionService.SessionStatus.EXPIRED, status,
                    "同一过期凭据重复请求的原因必须稳定为 EXPIRED，不得漂移为 UNKNOWN");
        }
        // 原子认证入口同样稳定，且续期不复活
        for (int i = 0; i < 3; i++) {
            SessionService.SessionAuthResult auth = sessions.authenticate(s.sessionId());
            assertEquals(SessionService.SessionStatus.EXPIRED, auth.status());
            assertNull(auth.touch());
        }
        assertTrue(sessions.find(s.sessionId()).isEmpty(), "过期凭据始终不可用");
    }

    @Test
    void revokeAfterExpiryWinsAndStaysUnknown() {
        LoginGuardTest.MutableClock clock = new LoginGuardTest.MutableClock(T0);
        SessionService sessions = new SessionService(props(), clock);
        SessionRecord s = sessions.create("alice", Set.of(Role.USER));
        clock.advance(Duration.ofMinutes(31));
        assertEquals(SessionService.SessionStatus.EXPIRED, sessions.evaluate(s.sessionId()).status());
        // 过期后再显式撤销：以撤销为准，且保持稳定
        sessions.revoke(s.sessionId());
        for (int i = 0; i < 3; i++) {
            assertEquals(SessionService.SessionStatus.UNKNOWN,
                    sessions.evaluate(s.sessionId()).status(), "撤销优先于过期，且不得漂回 EXPIRED");
            assertTrue(sessions.touch(s.sessionId()).isEmpty(), "已撤销墓碑不得被续期复活");
        }
        log.info("decision: revoke-after-expiry converges to UNKNOWN and stays");
    }

    @Test
    void tombstoneIsPurgedOnlyAfterRetentionWindow() {
        LoginGuardTest.MutableClock clock = new LoginGuardTest.MutableClock(T0);
        SessionService sessions = new SessionService(props(), clock);
        SessionRecord s = sessions.create("alice", Set.of(Role.USER));
        clock.advance(Duration.ofMinutes(31)); // 过期
        assertEquals(SessionService.SessionStatus.EXPIRED, sessions.evaluate(s.sessionId()).status());
        // 越过绝对上限(2h)但仍在保留窗口(1h)内：仍稳定 EXPIRED（31+148=179m < 180m）
        clock.advance(Duration.ofMinutes(148));
        assertEquals(SessionService.SessionStatus.EXPIRED, sessions.evaluate(s.sessionId()).status());
        // 超过绝对上限 + 保留窗口后：墓碑清除，变为 UNKNOWN（有界内存，不影响稳定性承诺窗口）
        clock.advance(Duration.ofMinutes(2));
        assertEquals(SessionService.SessionStatus.UNKNOWN, sessions.evaluate(s.sessionId()).status());
        log.info("decision: tombstone retained through absolute cap + retention, then purged");
    }
}
