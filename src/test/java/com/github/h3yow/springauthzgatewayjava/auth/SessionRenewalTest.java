package com.github.h3yow.springauthzgatewayjava.auth;

import static org.junit.jupiter.api.Assertions.*;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** 会话滑动续期：空闲阈值、绝对上限、续期与撤销竞争时的收敛。 */
class SessionRenewalTest {

    private static final Logger log = LoggerFactory.getLogger(SessionRenewalTest.class);
    private static final Instant T0 = Instant.parse("2026-09-27T00:00:00Z");

    private AuthProperties props() {
        AuthProperties p = new AuthProperties();
        p.setSessionTtl(Duration.ofMinutes(30));
        p.setSessionMaxLifetime(Duration.ofHours(2));
        return p;
    }

    @Test
    void activityBeforeIdleThresholdDoesNotExtendExpiry() {
        LoginGuardTest.MutableClock clock = new LoginGuardTest.MutableClock(T0);
        SessionService sessions = new SessionService(props(), clock);
        SessionRecord s = sessions.create("alice", Set.of(Role.USER));
        clock.advance(Duration.ofMinutes(10)); // 不足 ttl 一半（15m）
        Optional<SessionService.TouchResult> touch = sessions.touch(s.sessionId());
        log.info("input: touch at age=10m (half-ttl=15m) -> renewed={}", touch.get().renewed());
        assertTrue(touch.isPresent());
        assertFalse(touch.get().renewed(), "剩余有效期过半前不顺延");
        assertEquals(s.expiresAt(), touch.get().record().expiresAt());
        assertEquals(T0.plus(Duration.ofMinutes(10)), touch.get().record().lastUsedAt(),
                "最近使用时间必须随使用更新");
    }

    @Test
    void activityNearIdleThresholdExtendsExpiry() {
        LoginGuardTest.MutableClock clock = new LoginGuardTest.MutableClock(T0);
        SessionService sessions = new SessionService(props(), clock);
        SessionRecord s = sessions.create("alice", Set.of(Role.USER));
        clock.advance(Duration.ofMinutes(20)); // 超过一半，剩余 10m
        Optional<SessionService.TouchResult> touch = sessions.touch(s.sessionId());
        log.info("input: touch at age=20m ttl=30m -> renewed={} newExpiry={}",
                touch.get().renewed(), touch.get().record().expiresAt());
        assertTrue(touch.get().renewed(), "剩余不足一半时必须顺延");
        assertEquals(T0.plus(Duration.ofMinutes(50)), touch.get().record().expiresAt());
        // 顺延后的会话在原来的过期点（30m）之后、新过期点（50m）之前仍可用
        clock.advance(Duration.ofMinutes(15)); // 总计 35m，超过原 30m 空闲阈值
        assertTrue(sessions.find(s.sessionId()).isPresent(), "续期后不得按原过期点失效");
    }

    @Test
    void renewalNeverExceedsAbsoluteMaxLifetime() {
        LoginGuardTest.MutableClock clock = new LoginGuardTest.MutableClock(T0);
        SessionService sessions = new SessionService(props(), clock);
        SessionRecord s = sessions.create("alice", Set.of(Role.USER));
        // 持续活动，多次续期（5 × 20m = 100m，均在上限 120m 之前）
        for (int i = 0; i < 5; i++) {
            clock.advance(Duration.ofMinutes(20));
            Optional<SessionService.TouchResult> touch = sessions.touch(s.sessionId());
            assertTrue(touch.isPresent(), "绝对上限前持续活动必须保持有效");
            assertTrue(!touch.get().record().expiresAt().isAfter(s.absoluteExpiresAt()),
                    "续期不得超越绝对上限");
        }
        // 最后一次续期被绝对上限截断：expiresAt == 上限，而不是 now+30m
        Optional<SessionService.TouchResult> capped = sessions.touch(s.sessionId());
        assertEquals(s.absoluteExpiresAt(), capped.get().record().expiresAt(),
                "到达绝对上限后过期时间必须被截断在上限");
        // 越过绝对上限后：会话失效，续期不得复活
        clock.advance(Duration.ofMinutes(21)); // 总计 121m > 120m 上限
        Optional<SessionService.TouchResult> atCap = sessions.touch(s.sessionId());
        log.info("input: touch beyond max-lifetime=2h -> present={}", atCap.isPresent());
        assertTrue(atCap.isEmpty(), "超过绝对上限后会话必须失效，续期不得复活");
        assertTrue(sessions.find(s.sessionId()).isEmpty());
    }

    @Test
    void revokedSessionIsNotRevivedByRenewal() {
        LoginGuardTest.MutableClock clock = new LoginGuardTest.MutableClock(T0);
        SessionService sessions = new SessionService(props(), clock);
        SessionRecord s = sessions.create("alice", Set.of(Role.USER));
        sessions.revoke(s.sessionId());
        clock.advance(Duration.ofMinutes(20));
        Optional<SessionService.TouchResult> touch = sessions.touch(s.sessionId());
        log.info("input: touch revoked session -> present={}", touch.isPresent());
        assertTrue(touch.isEmpty(), "已撤销会话不得因续期复活");
        assertTrue(sessions.find(s.sessionId()).isEmpty());
    }

    @Test
    void expiredSessionIsNotRevivedByRenewal() {
        LoginGuardTest.MutableClock clock = new LoginGuardTest.MutableClock(T0);
        SessionService sessions = new SessionService(props(), clock);
        SessionRecord s = sessions.create("alice", Set.of(Role.USER));
        clock.advance(Duration.ofMinutes(31)); // 空闲超时
        Optional<SessionService.TouchResult> touch = sessions.touch(s.sessionId());
        log.info("input: touch expired session (age=31m ttl=30m) -> present={}", touch.isPresent());
        assertTrue(touch.isEmpty(), "已过期会话不得因续期复活");
        assertTrue(sessions.find(s.sessionId()).isEmpty());
    }

    @Test
    void concurrentRenewalAndRevokeConvergeToRevoked() throws InterruptedException {
        LoginGuardTest.MutableClock clock = new LoginGuardTest.MutableClock(T0);
        SessionService sessions = new SessionService(props(), clock);
        SessionRecord s = sessions.create("alice", Set.of(Role.USER));
        int threads = 32;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger touchAfterRevoke = new AtomicInteger();
        // 一个线程撤销，其余线程并发续期
        pool.submit(() -> {
            try {
                start.await();
                sessions.revoke(s.sessionId());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });
        for (int i = 0; i < threads - 1; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    Thread.sleep(5); // 让撤销大概率先完成
                    sessions.touch(s.sessionId());
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(10, TimeUnit.SECONDS));
        // 全部完成后：会话必须处于已撤销状态，任何续期不得使其复活
        sessions.touch(s.sessionId()).ifPresent(t -> touchAfterRevoke.incrementAndGet());
        log.info("input: concurrent revoke + {} touches -> final find present={}",
                threads - 1, sessions.find(s.sessionId()).isPresent());
        assertEquals(0, touchAfterRevoke.get());
        assertTrue(sessions.find(s.sessionId()).isEmpty(), "竞争结束后必须收敛到已撤销");
    }
}
