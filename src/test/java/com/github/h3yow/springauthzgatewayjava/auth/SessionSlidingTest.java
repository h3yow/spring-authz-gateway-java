package com.github.h3yow.springauthzgatewayjava.auth;

import static org.junit.jupiter.api.Assertions.*;

import java.time.Duration;
import java.time.Instant;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 会话滑动续期：空闲阈值顺延、绝对上限不可突破、续期与撤销竞争时撤销为准、墓碑绝不复活。
 */
class SessionSlidingTest {

    private static final Logger log = LoggerFactory.getLogger(SessionSlidingTest.class);

    private AuthProperties props(Duration idle, Duration max) {
        AuthProperties p = new AuthProperties();
        p.setSessionTtl(idle);
        p.setSessionIdleTtl(idle);
        p.setSessionMaxTtl(max);
        return p;
    }

    @Test
    void activityWithinIdleWindowSlidesExpiry() {
        LoginGuardTest.MutableClock clock =
                new LoginGuardTest.MutableClock(Instant.parse("2026-09-27T00:00:00Z"));
        SessionService sessions = new SessionService(props(Duration.ofMinutes(30), Duration.ofHours(12)), clock);
        SessionRecord s = sessions.create("alice", Set.of(Role.USER), "10.0.0.1");

        clock.advance(Duration.ofMinutes(20));
        SessionRecord used1 = sessions.find(s.sessionId()).orElseThrow();
        log.info("input: use at +20m, idleTtl=30m -> lastUsedAt advanced, idle expiry extended");
        assertEquals(clock.instant(), used1.lastUsedAt());

        // 距签发已 40m（超过初始空闲 30m），但距最近使用仅 20m，滑动后应仍有效
        clock.advance(Duration.ofMinutes(20));
        assertTrue(sessions.find(s.sessionId()).isPresent(), "持续使用应滑动续期，不得按初始空闲时间失效");
        log.info("decision: session still valid at +40m due to sliding");
    }

    @Test
    void idleBeyondThresholdExpiresEvenIfNeverAbsolute() {
        LoginGuardTest.MutableClock clock =
                new LoginGuardTest.MutableClock(Instant.parse("2026-09-27T00:00:00Z"));
        SessionService sessions = new SessionService(props(Duration.ofMinutes(30), Duration.ofHours(12)), clock);
        SessionRecord s = sessions.create("alice", Set.of(Role.USER), "10.0.0.1");
        clock.advance(Duration.ofMinutes(31));
        assertTrue(sessions.find(s.sessionId()).isEmpty(), "空闲超过阈值必须失效");
        log.info("input: idle 31m > 30m -> rejected (absolute cap 12h not the cause)");
    }

    @Test
    void slidingNeverExceedsAbsoluteCap() {
        LoginGuardTest.MutableClock clock =
                new LoginGuardTest.MutableClock(Instant.parse("2026-09-27T00:00:00Z"));
        SessionService sessions = new SessionService(props(Duration.ofMinutes(30), Duration.ofMinutes(40)), clock);
        SessionRecord s = sessions.create("alice", Set.of(Role.USER), "10.0.0.1");

        // 持续使用（每 20m 一次），空闲窗口不断顺延，但绝对上限 40m 不可突破
        clock.advance(Duration.ofMinutes(20));
        SessionRecord at20 = sessions.find(s.sessionId()).orElseThrow();
        assertEquals(s.absoluteExpiresAt(), at20.expiresAt(),
                "空闲顺延超过绝对上限时，真实失效时间必须被截断到绝对上限");

        clock.advance(Duration.ofMinutes(19));
        assertTrue(sessions.find(s.sessionId()).isPresent(), "绝对上限前一刻仍应有效");
        log.info("input: continuously used, t=39m < absolute cap 40m -> valid");

        clock.advance(Duration.ofMinutes(2)); // t=41m
        assertTrue(sessions.find(s.sessionId()).isEmpty(), "达到绝对上限后即使持续使用也必须失效");
        log.info("decision: expired at absolute cap despite continuous activity");
    }

    @Test
    void revokeBeatsConcurrentTouchAndNeverReactivates() throws InterruptedException {
        SessionService sessions =
                new SessionService(props(Duration.ofMinutes(30), Duration.ofHours(12)));
        SessionRecord s = sessions.create("alice", Set.of(Role.USER), "10.0.0.1");
        int threads = 16;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger touchesAfterRevoke = new AtomicInteger();

        // 1 个线程撤销
        pool.submit(() -> {
            try {
                start.await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            sessions.revoke(s.sessionId());
        });
        // 其余线程并发"使用"（滑动续期），撤销完成后再使用一小段时间
        for (int i = 1; i < threads; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    for (int j = 0; j < 50; j++) {
                        if (sessions.find(s.sessionId()).isPresent()) {
                            touchesAfterRevoke.incrementAndGet();
                        }
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(15, TimeUnit.SECONDS));

        assertTrue(sessions.find(s.sessionId()).isEmpty(), "撤销后任何续期都不得使其复活");
        assertEquals(CredentialState.REVOKED, sessions.stateOf(s.sessionId()),
                "撤销墓碑必须可稳定判定为 REVOKED，而非不存在");
        // 撤销提交之后的滑动调用可能与撤销窗口交叠，但撤销完成后再不得被接受：
        // 再做一轮纯串行校验，必须全部失败
        for (int i = 0; i < 100; i++) {
            assertTrue(sessions.find(s.sessionId()).isEmpty());
        }
        log.info("input: concurrent revoke vs sliding touches, post-revoke overlapping accepts={}",
                touchesAfterRevoke.get());
    }

    @Test
    void expiredSessionCannotBeReactivatedByTouch() {
        LoginGuardTest.MutableClock clock =
                new LoginGuardTest.MutableClock(Instant.parse("2026-09-27T00:00:00Z"));
        SessionService sessions = new SessionService(props(Duration.ofMinutes(30), Duration.ofHours(12)), clock);
        SessionRecord s = sessions.create("alice", Set.of(Role.USER), "10.0.0.1");
        clock.advance(Duration.ofMinutes(45));
        assertTrue(sessions.find(s.sessionId()).isEmpty(), "已过期会话不得被使用救活");
        clock.advance(Duration.ofMinutes(1));
        assertTrue(sessions.find(s.sessionId()).isEmpty(), "过期后继续使用仍必须失效");
        log.info("decision: expired session stays expired under repeated touch");
    }

    @Test
    void revokeForUserExceptKeepsOnlyDesignatedSession() {
        SessionService sessions =
                new SessionService(props(Duration.ofMinutes(30), Duration.ofHours(12)));
        SessionRecord s1 = sessions.create("alice", Set.of(Role.USER), "client-a");
        SessionRecord keep = sessions.create("alice", Set.of(Role.USER), "client-b");
        SessionRecord s3 = sessions.create("alice", Set.of(Role.USER), "client-c");
        SessionRecord bob = sessions.create("bob", Set.of(Role.USER), "client-d");

        int count = sessions.revokeForUserExcept("alice", keep.sessionId());
        assertEquals(2, count, "应撤销除当前会话外的另外两个");
        assertTrue(sessions.find(s1.sessionId()).isEmpty());
        assertTrue(sessions.find(s3.sessionId()).isEmpty());
        assertTrue(sessions.find(keep.sessionId()).isPresent(), "当前会话必须保持可用");
        assertTrue(sessions.find(bob.sessionId()).isPresent(), "其他用户会话不得受影响");
        // 重复调用幂等
        assertEquals(0, sessions.revokeForUserExcept("alice", keep.sessionId()));
        log.info("decision: only the designated current session remains usable");
    }
}
