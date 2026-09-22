package com.github.h3yow.springauthzgatewayjava.auth;

import static org.junit.jupiter.api.Assertions.*;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class TokenServiceTest {

    private static final Logger log = LoggerFactory.getLogger(TokenServiceTest.class);

    private AuthProperties props() {
        AuthProperties p = new AuthProperties();
        p.setAccessTokenTtl(Duration.ofMinutes(10));
        p.setRefreshTokenTtl(Duration.ofHours(12));
        return p;
    }

    private TokenService newService() {
        return new TokenService(props(), new LoginGuardTest.MutableClock(Instant.now()), new byte[32]);
    }

    @Test
    void issuedAccessTokenVerifies() {
        TokenService tokens = newService();
        TokenService.TokenPair pair = tokens.issue("alice", Set.of(Role.USER));
        Optional<TokenService.TokenSubject> subject = tokens.verifyAccessToken(pair.accessToken());
        log.info("input: freshly issued access token -> verified={}", subject.isPresent());
        assertTrue(subject.isPresent());
        assertEquals("alice", subject.get().username());
        assertEquals(Set.of(Role.USER), subject.get().roles());
    }

    @Test
    void forgedOrTamperedTokenRejected() {
        TokenService tokens = newService();
        TokenService.TokenPair pair = tokens.issue("alice", Set.of(Role.USER));
        String tampered = pair.accessToken().substring(0, pair.accessToken().length() - 2) + "xx";
        log.info("input: tampered token, garbage token, refresh-as-access");
        assertTrue(tokens.verifyAccessToken(tampered).isEmpty(), "篡改签名必须拒绝");
        assertTrue(tokens.verifyAccessToken("garbage").isEmpty(), "畸形令牌必须拒绝");
        assertTrue(tokens.verifyAccessToken(pair.refreshToken()).isEmpty(), "刷新令牌不得当访问令牌用");
        log.info("decision: all rejected");
    }

    @Test
    void expiredTokenRejected() {
        LoginGuardTest.MutableClock clock =
                new LoginGuardTest.MutableClock(Instant.parse("2026-09-22T00:00:00Z"));
        TokenService tokens = new TokenService(props(), clock, new byte[32]);
        TokenService.TokenPair pair = tokens.issue("alice", Set.of(Role.USER));
        clock.advance(Duration.ofMinutes(11));
        log.info("input: access token age=11m ttl=10m");
        assertTrue(tokens.verifyAccessToken(pair.accessToken()).isEmpty(), "过期令牌必须拒绝");
        log.info("decision: expired token rejected");
    }

    @Test
    void revokeAllForUserInvalidatesImmediately() {
        TokenService tokens = newService();
        TokenService.TokenPair pair = tokens.issue("alice", Set.of(Role.USER));
        tokens.revokeAllForUser("alice");
        log.info("input: revokeAllForUser(alice) then verify previously issued tokens");
        assertTrue(tokens.verifyAccessToken(pair.accessToken()).isEmpty(), "撤销后访问令牌必须立即失效");
        assertTrue(tokens.refresh(pair.refreshToken()).isEmpty(), "撤销后刷新令牌必须立即失效");
        log.info("decision: both rejected after revocation");
    }

    @Test
    void refreshRotatesAndOldTokenSingleUse() {
        TokenService tokens = newService();
        TokenService.TokenPair first = tokens.issue("alice", Set.of(Role.USER));
        Optional<TokenService.TokenPair> second = tokens.refresh(first.refreshToken());
        log.info("input: refresh once, then reuse old refresh token");
        assertTrue(second.isPresent());
        assertTrue(tokens.refresh(first.refreshToken()).isEmpty(), "旧刷新令牌不得重复使用");
        assertTrue(tokens.verifyAccessToken(first.accessToken()).isPresent(),
                "旋转不得误伤未撤销的旧访问令牌（短有效期内）");
    }

    @Test
    void concurrentRefreshSucceedsExactlyOnce() throws InterruptedException {
        TokenService tokens = newService();
        TokenService.TokenPair pair = tokens.issue("alice", Set.of(Role.USER));
        int threads = 32;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger successes = new AtomicInteger();
        Set<String> issuedAccess = ConcurrentHashMap.newKeySet();
        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    tokens.refresh(pair.refreshToken()).ifPresent(p -> {
                        successes.incrementAndGet();
                        issuedAccess.add(p.accessToken());
                    });
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(15, TimeUnit.SECONDS));
        log.info("input: {} threads refresh same token concurrently -> successes={} distinctAccessTokens={}",
                threads, successes.get(), issuedAccess.size());
        assertEquals(1, successes.get(), "并发刷新必须恰好成功一次，不得重复签发");
        assertEquals(1, issuedAccess.size());
    }

    @Test
    void concurrentRevokeAndVerifyNeverAcceptsRevoked() throws InterruptedException {
        TokenService tokens = newService();
        TokenService.TokenPair pair = tokens.issue("alice", Set.of(Role.USER));
        ExecutorService pool = Executors.newFixedThreadPool(8);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger acceptedAfterRevoke = new AtomicInteger();
        pool.submit(() -> {
            try {
                start.await();
                tokens.revokeAllForUser("alice");
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });
        for (int i = 0; i < 7; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    Thread.sleep(5); // 撤销完成后校验
                    if (tokens.verifyAccessToken(pair.accessToken()).isPresent()) {
                        acceptedAfterRevoke.incrementAndGet();
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(10, TimeUnit.SECONDS));
        log.info("input: concurrent revoke + verify -> accepted after revoke={}", acceptedAfterRevoke.get());
        assertEquals(0, acceptedAfterRevoke.get(), "撤销完成后任何线程不得再接受该令牌");
    }
}
