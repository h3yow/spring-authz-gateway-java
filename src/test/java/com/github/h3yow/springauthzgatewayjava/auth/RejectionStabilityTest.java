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
 * 同一凭据拒绝原因稳定性：已过期 / 已撤销在重复请求下不漂移、
 * 撤销与续期并发竞争以撤销为准、并发重复撤销收敛到同一终态。
 */
class RejectionStabilityTest {

    private static final Logger log = LoggerFactory.getLogger(RejectionStabilityTest.class);
    private static final Instant T0 = Instant.parse("2026-09-28T00:00:00Z");

    private AuthProperties props() {
        AuthProperties p = new AuthProperties();
        p.setSessionTtl(Duration.ofMinutes(30));
        p.setSessionMaxLifetime(Duration.ofHours(2));
        p.setAccessTokenTtl(Duration.ofMinutes(10));
        return p;
    }

    @Test
    void expiredSessionReasonStaysExpiredAcrossRepeatedRequests() {
        LoginGuardTest.MutableClock clock = new LoginGuardTest.MutableClock(T0);
        SessionService sessions = new SessionService(props(), clock);
        SessionRecord s = sessions.create("alice", Set.of(Role.USER));
        clock.advance(Duration.ofMinutes(31)); // 空闲超时
        for (int i = 0; i < 10; i++) {
            SessionService.SessionStatus status = sessions.evaluate(s.sessionId()).status();
            log.info("input: expired session evaluate #{} -> {}", i + 1, status);
            assertEquals(SessionService.SessionStatus.EXPIRED, status,
                    "过期凭据重复请求必须稳定为 EXPIRED，不得翻转为 UNKNOWN/撤销");
            assertTrue(sessions.touch(s.sessionId()).isEmpty(), "过期凭据不得因续期复活");
        }
        // 过期之后再撤销：原因仍保持 EXPIRED，不翻转
        sessions.revoke(s.sessionId());
        assertEquals(SessionService.SessionStatus.EXPIRED, sessions.evaluate(s.sessionId()).status(),
                "已过期终态不得被后续撤销翻转为撤销");
    }

    @Test
    void revokedSessionReasonStaysRevokedAcrossRepeatedRequests() throws InterruptedException {
        SessionService sessions = new SessionService(props());
        SessionRecord s = sessions.create("alice", Set.of(Role.USER));
        sessions.revoke(s.sessionId());
        for (int i = 0; i < 10; i++) {
            assertEquals(SessionService.SessionStatus.UNKNOWN, sessions.evaluate(s.sessionId()).status(),
                    "撤销凭据重复请求必须稳定表现为 UNKNOWN/撤销");
        }
        // 并发重复撤销同一凭据，结果收敛
        int threads = 16;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    sessions.revoke(s.sessionId());
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(10, TimeUnit.SECONDS));
        assertEquals(SessionService.SessionStatus.UNKNOWN, sessions.evaluate(s.sessionId()).status());
        assertTrue(sessions.find(s.sessionId()).isEmpty());
    }

    @Test
    void revokeAllAndRevokeOthersConvergeToRevoked() {
        SessionService sessions = new SessionService(props());
        SessionRecord a = sessions.create("alice", Set.of(Role.USER));
        SessionRecord b = sessions.create("alice", Set.of(Role.USER));
        sessions.revokeAllForUser("alice");
        sessions.revokeAllForUserExcept("alice", a.sessionId()); // 全部已终态：no-op
        sessions.revoke(a.sessionId());
        sessions.revoke(b.sessionId());
        assertEquals(SessionService.SessionStatus.UNKNOWN, sessions.evaluate(a.sessionId()).status());
        assertEquals(SessionService.SessionStatus.UNKNOWN, sessions.evaluate(b.sessionId()).status());
    }

    @Test
    void concurrentRenewalAndRevokeConvergesToRevoked() throws InterruptedException {
        LoginGuardTest.MutableClock clock = new LoginGuardTest.MutableClock(T0);
        SessionService sessions = new SessionService(props(), clock);
        SessionRecord s = sessions.create("alice", Set.of(Role.USER));
        // 确定性收敛：撤销先完成，随后任意多个续期并发冲击
        sessions.revoke(s.sessionId());
        int threads = 31;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger touchSucceeded = new AtomicInteger();
        AtomicInteger wrongStatus = new AtomicInteger();
        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    sessions.touch(s.sessionId()).ifPresent(t -> touchSucceeded.incrementAndGet());
                    if (sessions.evaluate(s.sessionId()).status()
                            != SessionService.SessionStatus.UNKNOWN) {
                        wrongStatus.incrementAndGet();
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(10, TimeUnit.SECONDS));
        assertEquals(0, touchSucceeded.get(), "撤销完成后任何续期都不得成功");
        assertEquals(0, wrongStatus.get(), "撤销终态在并发续期冲击下必须稳定");
        // 再补一轮"撤销 + 续期"真正同时起跑的压力，最终仍必须收敛到撤销
        ExecutorService pool2 = Executors.newFixedThreadPool(threads + 1);
        CountDownLatch race = new CountDownLatch(1);
        AtomicInteger revived = new AtomicInteger();
        for (int i = 0; i < threads; i++) {
            pool2.submit(() -> {
                try {
                    race.await();
                    sessions.touch(s.sessionId()).ifPresent(t -> revived.incrementAndGet());
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        pool2.submit(() -> {
            try {
                race.await();
                sessions.revoke(s.sessionId());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });
        race.countDown();
        pool2.shutdown();
        assertTrue(pool2.awaitTermination(10, TimeUnit.SECONDS));
        assertEquals(0, revived.get(), "终态后任何续期都不得使其复活");
        assertEquals(SessionService.SessionStatus.UNKNOWN, sessions.evaluate(s.sessionId()).status(),
                "续期与撤销竞争最终必须以撤销为准");
    }

    @Test
    void expiredAccessTokenReasonStaysExpiredAndRevokedStaysInvalid() {
        LoginGuardTest.MutableClock clock = new LoginGuardTest.MutableClock(T0);
        TokenService tokens = new TokenService(props(), clock, new byte[32]);
        // 未被撤销的令牌过期：稳定 EXPIRED
        TokenService.TokenPair expired = tokens.issue("alice", Set.of(Role.USER));
        clock.advance(Duration.ofMinutes(11));
        for (int i = 0; i < 5; i++) {
            assertEquals(TokenService.TokenStatus.EXPIRED,
                    tokens.evaluateAccessToken(expired.accessToken()),
                    "未撤销的过期令牌重复判定必须稳定为 EXPIRED");
        }
        // 撤销后（宽限窗口内）越过 exp：仍稳定 INVALID，不漂移为 EXPIRED
        TokenService.TokenPair pair = tokens.issue("bob", Set.of(Role.USER));
        String cid = tokens.credentialIdOf(pair.accessToken()).orElseThrow();
        tokens.revokeByCredentialId("bob", cid);
        assertEquals(TokenService.TokenStatus.INVALID, tokens.evaluateAccessToken(pair.accessToken()));
        clock.advance(Duration.ofMinutes(30)); // 远超令牌自身 10m 有效期，但仍在撤销宽限窗口内
        assertEquals(TokenService.TokenStatus.INVALID, tokens.evaluateAccessToken(pair.accessToken()),
                "已撤销令牌不得因到达 exp 漂移为 EXPIRED");
        log.info("decision: expired->EXPIRED stable; revoked-then-expired->INVALID stable");
    }

    @Test
    void sessionTombstoneIsPurgedOnlyAfterRetentionWindow() {
        LoginGuardTest.MutableClock clock = new LoginGuardTest.MutableClock(T0);
        SessionService sessions = new SessionService(props(), clock);
        SessionRecord s = sessions.create("alice", Set.of(Role.USER));
        clock.advance(Duration.ofMinutes(31)); // 空闲超时
        assertEquals(SessionService.SessionStatus.EXPIRED, sessions.evaluate(s.sessionId()).status());
        // 保留到 max(空闲失效 30m, 绝对上限 2h) + 一个空闲 TTL(30m) = 2h30m；窗口内原因稳定
        clock.advance(Duration.ofMinutes(118)); // 总计 149m，保留窗口 150m 之前
        assertEquals(SessionService.SessionStatus.EXPIRED, sessions.evaluate(s.sessionId()).status(),
                "保留窗口（绝对上限+1 个 TTL）内墓碑不得消失");
        clock.advance(Duration.ofMinutes(2)); // 151m，超过 2h30m
        assertEquals(SessionService.SessionStatus.UNKNOWN, sessions.evaluate(s.sessionId()).status(),
                "超过保留窗口后墓碑惰性清理，凭据回归未知");
    }
}
