package com.github.h3yow.springauthzgatewayjava.auth;

import static org.junit.jupiter.api.Assertions.*;

import java.time.Duration;
import java.time.Instant;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 撤销收敛：续期与撤销竞争、单个撤销/撤销全部/并发重复撤销最终一致——
 * 已撤销或已过期的凭据不会因任何一次续期或并发交错复活。
 */
class RevocationConvergenceTest {

    private static final Logger log = LoggerFactory.getLogger(RevocationConvergenceTest.class);
    private static final Instant T0 = Instant.parse("2026-09-28T00:00:00Z");

    private AuthProperties props() {
        AuthProperties p = new AuthProperties();
        p.setSessionTtl(Duration.ofMinutes(30));
        p.setSessionMaxLifetime(Duration.ofHours(2));
        p.setAccessTokenTtl(Duration.ofMinutes(10));
        p.setRefreshTokenTtl(Duration.ofHours(2));
        p.setRevocationRetention(Duration.ofHours(1));
        return p;
    }

    @Test
    void concurrentDuplicateSessionRevokesConvergeToRevoked() throws InterruptedException {
        SessionService sessions = new SessionService(props());
        SessionRecord s = sessions.create("alice", Set.of(Role.USER));
        runParallel(32, () -> sessions.revoke(s.sessionId()));
        assertTrue(sessions.find(s.sessionId()).isEmpty());
        assertEquals(SessionService.SessionStatus.UNKNOWN, sessions.evaluate(s.sessionId()).status());
        // 撤销后任何续期都不得复活
        assertTrue(sessions.touch(s.sessionId()).isEmpty());
        log.info("decision: 32 concurrent duplicate session revokes -> single stable UNKNOWN");
    }

    @Test
    void revokeOneAndRevokeAllRacingConvergeToRevoked() throws InterruptedException {
        SessionService sessions = new SessionService(props());
        TokenService tokens = new TokenService(props(), new LoginGuardTest.MutableClock(T0), new byte[32]);
        CredentialManager manager = new CredentialManager(sessions, tokens);
        SessionRecord s = sessions.create("alice", Set.of(Role.USER), "agent-x");
        TokenService.TokenPair pair = tokens.issue("alice", Set.of(Role.USER), "agent-x");
        String cid = tokens.credentialIdOf(pair.accessToken()).orElseThrow();

        // 同一凭据上"撤销单个"与"撤销其他全部"并发交错，重复多轮
        runParallel(32, () -> {
            manager.revokeOne("alice", s.credentialId());
            manager.revokeAllExcept("alice", CredentialManager.CurrentCredential.token(cid));
            manager.revokeOne("alice", cid);
        });
        // 无论交错顺序如何，最终全部凭据必须处于撤销态
        assertTrue(sessions.find(s.sessionId()).isEmpty(), "会话最终必须撤销");
        assertEquals(TokenService.TokenStatus.INVALID, tokens.evaluateAccessToken(pair.accessToken()),
                "令牌最终必须撤销，且稳定 INVALID");
        log.info("decision: racing revoke-one/revoke-others converge to fully revoked");
    }

    @Test
    void concurrentDuplicateTokenRevokesConvergeToInvalid() throws InterruptedException {
        TokenService tokens = new TokenService(props(), new LoginGuardTest.MutableClock(T0), new byte[32]);
        TokenService.TokenPair pair = tokens.issue("alice", Set.of(Role.USER));
        String cid = tokens.credentialIdOf(pair.accessToken()).orElseThrow();
        runParallel(32, () -> {
            tokens.revokeByCredentialId("alice", cid);
            tokens.revokeAllForUser("alice");
        });
        for (int i = 0; i < 3; i++) {
            assertEquals(TokenService.TokenStatus.INVALID, tokens.evaluateAccessToken(pair.accessToken()));
        }
        assertTrue(tokens.verifyAccessToken(pair.accessToken()).isEmpty());
        log.info("decision: 32 concurrent duplicate token revokes -> stable INVALID");
    }

    @Test
    void renewalNeverWinsAgainstRevokedOrExpiredCredential() {
        LoginGuardTest.MutableClock clock = new LoginGuardTest.MutableClock(T0);
        SessionService sessions = new SessionService(props(), clock);
        // 已过期：续期不复活，且原因稳定
        SessionRecord expired = sessions.create("alice", Set.of(Role.USER));
        clock.advance(Duration.ofMinutes(31));
        assertEquals(SessionService.SessionStatus.EXPIRED, sessions.authenticate(expired.sessionId()).status());
        assertNull(sessions.authenticate(expired.sessionId()).touch());
        // 已撤销：续期不复活
        clock.advance(Duration.ofMinutes(-31));
        SessionRecord live = sessions.create("alice", Set.of(Role.USER));
        sessions.revoke(live.sessionId());
        clock.advance(Duration.ofMinutes(20));
        assertTrue(sessions.touch(live.sessionId()).isEmpty());
        log.info("decision: neither expired nor revoked credential can be revived by renewal");
    }

    private static void runParallel(int threads, Runnable task) throws InterruptedException {
        ExecutorService pool = Executors.newFixedThreadPool(Math.min(threads, 16));
        CountDownLatch start = new CountDownLatch(1);
        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    task.run();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(15, TimeUnit.SECONDS));
    }
}
