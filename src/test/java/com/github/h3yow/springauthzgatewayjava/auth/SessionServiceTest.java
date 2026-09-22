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

class SessionServiceTest {

    private static final Logger log = LoggerFactory.getLogger(SessionServiceTest.class);

    private AuthProperties props() {
        AuthProperties p = new AuthProperties();
        p.setSessionTtl(Duration.ofMinutes(30));
        return p;
    }

    @Test
    void revokedSessionIsRejectedImmediately() {
        SessionService sessions = new SessionService(props());
        SessionRecord s = sessions.create("alice", Set.of(Role.USER));
        log.info("input: create session then revoke, sessionId={}", com.github.h3yow.springauthzgatewayjava.util.Masking.mask(s.sessionId()));
        assertTrue(sessions.find(s.sessionId()).isPresent());
        sessions.revoke(s.sessionId());
        Optional<SessionRecord> after = sessions.find(s.sessionId());
        log.info("decision: find after revoke -> present={}", after.isPresent());
        assertTrue(after.isEmpty(), "撤销后必须立即不可见");
        sessions.revoke(s.sessionId()); // 幂等
    }

    @Test
    void expiredSessionIsRejected() {
        LoginGuardTest.MutableClock clock =
                new LoginGuardTest.MutableClock(Instant.parse("2026-09-22T00:00:00Z"));
        SessionService sessions = new SessionService(props(), clock);
        SessionRecord s = sessions.create("alice", Set.of(Role.USER));
        clock.advance(Duration.ofMinutes(31));
        log.info("input: session age=31m ttl=30m");
        assertTrue(sessions.find(s.sessionId()).isEmpty(), "过期会话不得被接受");
        log.info("decision: expired session rejected");
    }

    @Test
    void revokeAllForUserOnlyAffectsThatUser() {
        SessionService sessions = new SessionService(props());
        SessionRecord a = sessions.create("alice", Set.of(Role.USER));
        SessionRecord b = sessions.create("bob", Set.of(Role.USER));
        sessions.revokeAllForUser("alice");
        log.info("input: revokeAllForUser(alice); check alice and bob sessions");
        assertTrue(sessions.find(a.sessionId()).isEmpty());
        assertTrue(sessions.find(b.sessionId()).isPresent(), "其他用户会话不得受影响");
    }

    @Test
    void concurrentRevokeAndFindYieldConsistentResults() throws InterruptedException {
        SessionService sessions = new SessionService(props());
        int n = 64;
        SessionRecord[] records = new SessionRecord[n];
        for (int i = 0; i < n; i++) {
            records[i] = sessions.create("user" + i, Set.of(Role.USER));
        }
        ExecutorService pool = Executors.newFixedThreadPool(16);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch revokesDone = new CountDownLatch(n);
        // 阶段一：并发撤销全部会话
        for (int i = 0; i < n; i++) {
            final int idx = i;
            pool.submit(() -> {
                try {
                    start.await();
                    sessions.revoke(records[idx].sessionId());
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    revokesDone.countDown();
                }
            });
        }
        start.countDown();
        assertTrue(revokesDone.await(10, TimeUnit.SECONDS), "全部撤销应在超时前完成");
        // 阶段二：撤销全部完成后，并发查询
        AtomicInteger foundAfterRevoke = new AtomicInteger();
        CountDownLatch findsDone = new CountDownLatch(n);
        for (int i = 0; i < n; i++) {
            final int idx = i;
            pool.submit(() -> {
                if (sessions.find(records[idx].sessionId()).isPresent()) {
                    foundAfterRevoke.incrementAndGet();
                }
                findsDone.countDown();
            });
        }
        assertTrue(findsDone.await(10, TimeUnit.SECONDS));
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(10, TimeUnit.SECONDS));
        log.info("input: {} sessions, concurrent revoke+find -> found after revoke={}", n, foundAfterRevoke.get());
        assertEquals(0, foundAfterRevoke.get(), "撤销后任何线程都不得再看到会话");
    }
}
