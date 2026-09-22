package com.github.h3yow.springauthzgatewayjava.auth;

import static org.junit.jupiter.api.Assertions.*;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class LoginGuardTest {

    private static final Logger log = LoggerFactory.getLogger(LoginGuardTest.class);

    /** 可推进的测试时钟。 */
    static final class MutableClock extends Clock {
        private Instant now;
        MutableClock(Instant start) { this.now = start; }
        void advance(Duration d) { now = now.plus(d); }
        @Override public Instant instant() { return now; }
        @Override public ZoneId getZone() { return ZoneId.of("UTC"); }
        @Override public Clock withZone(ZoneId zone) { return this; }
    }

    private AuthProperties props() {
        AuthProperties p = new AuthProperties();
        p.setLoginMaxFailures(3);
        p.setLoginFailureWindow(Duration.ofMinutes(5));
        p.setLockoutDuration(Duration.ofMinutes(10));
        return p;
    }

    @Test
    void locksAfterThresholdAndAutoRecovers() {
        MutableClock clock = new MutableClock(Instant.parse("2026-09-22T00:00:00Z"));
        LoginGuard guard = new LoginGuard(props(), clock);
        String key = "alice|10.0.0.1";

        log.info("input: 3 failures within window, threshold=3");
        guard.onFailure(key);
        guard.onFailure(key);
        assertFalse(guard.isBlocked(key), "未达阈值不得锁定");
        guard.onFailure(key);
        assertTrue(guard.isBlocked(key), "达到阈值必须锁定");
        log.info("decision: blocked=true lockedSecondsRemaining={}", guard.lockedSecondsRemaining(key));
        assertTrue(guard.lockedSecondsRemaining(key) > 0);

        log.info("input: advance clock past lockout duration (10m)");
        clock.advance(Duration.ofMinutes(11));
        assertFalse(guard.isBlocked(key), "锁定到期后需自动恢复");
        log.info("decision: blocked=false (auto-recovered)");
    }

    @Test
    void failuresOutsideWindowDoNotCount() {
        MutableClock clock = new MutableClock(Instant.parse("2026-09-22T00:00:00Z"));
        LoginGuard guard = new LoginGuard(props(), clock);
        String key = "bob|10.0.0.2";

        guard.onFailure(key);
        guard.onFailure(key);
        log.info("input: 2 failures, then advance beyond 5m window, then 1 more failure");
        clock.advance(Duration.ofMinutes(6));
        guard.onFailure(key);
        assertFalse(guard.isBlocked(key), "窗口外的旧失败不得计入");
        log.info("decision: blocked=false (old failures pruned)");
    }

    @Test
    void successClearsFailureCount() {
        LoginGuard guard = new LoginGuard(props());
        String key = "carol|10.0.0.3";
        guard.onFailure(key);
        guard.onFailure(key);
        guard.onSuccess(key);
        log.info("input: 2 failures then success then 2 failures, threshold=3");
        guard.onFailure(key);
        guard.onFailure(key);
        assertFalse(guard.isBlocked(key), "成功后计数应清零");
    }

    @Test
    void concurrentFailuresNeverExceedThresholdInconsistently() throws InterruptedException {
        LoginGuard guard = new LoginGuard(props());
        String key = "dave|10.0.0.4";
        int threads = 16;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger blockedObserved = new AtomicInteger();
        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    guard.onFailure(key);
                    if (guard.isBlocked(key)) {
                        blockedObserved.incrementAndGet();
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(10, TimeUnit.SECONDS));
        log.info("input: {} concurrent failures, threshold=3 -> blocked observed by {} threads",
                threads, blockedObserved.get());
        assertTrue(guard.isBlocked(key), "并发失败后必须一致处于锁定态");
        assertTrue(guard.lockedSecondsRemaining(key) > 0, "锁定状态不得出现半更新");
    }
}
