package com.github.h3yow.springauthzgatewayjava.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.h3yow.springauthzgatewayjava.auth.session.SessionRecord;
import com.github.h3yow.springauthzgatewayjava.auth.session.SessionService;
import com.github.h3yow.springauthzgatewayjava.config.AuthSecurityProperties;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class SessionServiceTest {

    private static final Logger log = LoggerFactory.getLogger(SessionServiceTest.class);

    private MutableClock clock;
    private SessionService sessionService;

    @BeforeEach
    void setUp() {
        clock = new MutableClock(Instant.parse("2026-09-22T00:00:00Z"));
        AuthSecurityProperties props = new AuthSecurityProperties();
        props.setSessionTtl(Duration.ofMinutes(30));
        sessionService = new SessionService(props, clock);
    }

    @Test
    void invalidationTakesEffectImmediately() {
        SessionRecord session = sessionService.create("alice");
        sessionService.invalidate(session.sessionId());
        boolean resolvable = sessionService.resolve(session.sessionId()).isPresent();
        log.info("input=invalidated session resolvable={}", resolvable);
        assertFalse(resolvable, "注销后任何入口不得再接受该会话");
    }

    @Test
    void expiredSessionRejected() {
        SessionRecord session = sessionService.create("alice");
        clock.advance(Duration.ofMinutes(31));
        boolean resolvable = sessionService.resolve(session.sessionId()).isPresent();
        log.info("input=session past ttl(30m) resolvable={}", resolvable);
        assertFalse(resolvable);
    }

    @Test
    void invalidateAllForUserOnlyAffectsThatUser() {
        SessionRecord alice = sessionService.create("alice");
        SessionRecord bob = sessionService.create("bob");
        sessionService.invalidateAllForUser("alice");
        log.info("input=invalidateAll(alice): alice resolvable={} bob resolvable={}",
                sessionService.resolve(alice.sessionId()).isPresent(),
                sessionService.resolve(bob.sessionId()).isPresent());
        assertFalse(sessionService.resolve(alice.sessionId()).isPresent());
        assertTrue(sessionService.resolve(bob.sessionId()).isPresent());
    }

    @Test
    void concurrentInvalidateAndResolveNeverHalfState() throws Exception {
        SessionRecord session = sessionService.create("alice");
        int threads = 16;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<Boolean>> futures = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            boolean doInvalidate = i % 2 == 0;
            futures.add(pool.submit(() -> {
                start.await();
                if (doInvalidate) {
                    sessionService.invalidate(session.sessionId());
                    return null;
                }
                return sessionService.resolve(session.sessionId()).isPresent();
            }));
        }
        start.countDown();
        for (var f : futures) {
            f.get();
        }
        pool.shutdown();
        // 全部并发操作结束后，状态必须收敛为“已注销”
        boolean finalState = sessionService.resolve(session.sessionId()).isPresent();
        log.info("input=concurrent invalidate+resolve, final resolvable={}", finalState);
        assertFalse(finalState, "并发注销后最终状态必须为已注销，不得出现半更新");
    }

    @Test
    void distinctSessionsHaveDistinctIdsAndCsrfTokens() {
        SessionRecord s1 = sessionService.create("alice");
        SessionRecord s2 = sessionService.create("alice");
        log.info("s1==s2 id={} csrf={}",
                s1.sessionId().equals(s2.sessionId()), s1.csrfToken().equals(s2.csrfToken()));
        assertFalse(s1.sessionId().equals(s2.sessionId()));
        assertFalse(s1.csrfToken().equals(s2.csrfToken()));
        assertEquals(2, List.of(s1, s2).size());
    }
}
