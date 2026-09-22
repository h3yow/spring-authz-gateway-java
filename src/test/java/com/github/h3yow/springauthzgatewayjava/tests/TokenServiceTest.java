package com.github.h3yow.springauthzgatewayjava.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.h3yow.springauthzgatewayjava.auth.token.TokenPair;
import com.github.h3yow.springauthzgatewayjava.auth.token.TokenService;
import com.github.h3yow.springauthzgatewayjava.config.AuthSecurityProperties;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class TokenServiceTest {

    private static final Logger log = LoggerFactory.getLogger(TokenServiceTest.class);

    private MutableClock clock;
    private AuthSecurityProperties props;
    private TokenService tokenService;

    @BeforeEach
    void setUp() {
        clock = new MutableClock(Instant.parse("2026-09-22T00:00:00Z"));
        props = new AuthSecurityProperties();
        props.setAccessTokenTtl(Duration.ofMinutes(10));
        props.setRefreshTokenTtl(Duration.ofHours(2));
        tokenService = new TokenService(props, clock);
    }

    @Test
    void issuedTokenValidates() {
        TokenPair pair = tokenService.issue("alice");
        var validated = tokenService.validate(pair.accessToken());
        log.info("input=issued token validate present={} user={}",
                validated.isPresent(), validated.map(TokenService.ValidatedToken::username).orElse("n/a"));
        assertTrue(validated.isPresent());
        assertEquals("alice", validated.get().username());
    }

    @Test
    void revokedTokenRejectedImmediately() {
        TokenPair pair = tokenService.issue("alice");
        tokenService.revoke(pair.accessToken());
        var validated = tokenService.validate(pair.accessToken());
        log.info("input=revoked token validate present={}", validated.isPresent());
        assertFalse(validated.isPresent(), "已撤销令牌不得在任何入口继续被接受");
    }

    @Test
    void tamperedTokenRejected() {
        TokenPair pair = tokenService.issue("alice");
        String tampered = pair.accessToken().substring(0, pair.accessToken().length() - 2) + "xx";
        log.info("input=tampered token validate present={}", tokenService.validate(tampered).isPresent());
        assertFalse(tokenService.validate(tampered).isPresent());
    }

    @Test
    void expiredTokenRejected() {
        TokenPair pair = tokenService.issue("alice");
        clock.advance(Duration.ofMinutes(11));
        log.info("input=expired token (ttl=10m, advanced 11m) validate present={}",
                tokenService.validate(pair.accessToken()).isPresent());
        assertFalse(tokenService.validate(pair.accessToken()).isPresent());
    }

    @Test
    void refreshRotatesAndOldRefreshTokenDead() {
        TokenPair first = tokenService.issue("alice");
        Optional<TokenPair> second = tokenService.refresh(first.refreshToken());
        assertTrue(second.isPresent());
        assertNotEquals(first.refreshToken(), second.get().refreshToken());
        Optional<TokenPair> replay = tokenService.refresh(first.refreshToken());
        log.info("input=reuse old refresh token -> success={}", replay.isPresent());
        assertFalse(replay.isPresent(), "旧刷新令牌已被消费，重放必须失败");
    }

    @Test
    void concurrentRefreshHasExactlyOneWinner() throws Exception {
        TokenPair pair = tokenService.issue("alice");
        int threads = 16;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<Optional<TokenPair>>> futures = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            futures.add(pool.submit(() -> {
                start.await();
                return tokenService.refresh(pair.refreshToken());
            }));
        }
        start.countDown();
        int winners = 0;
        for (var f : futures) {
            if (f.get().isPresent()) {
                winners++;
            }
        }
        pool.shutdown();
        log.info("input={} concurrent refreshes of same token, winners={}", threads, winners);
        assertEquals(1, winners, "并发刷新同一刷新令牌必须且只能有一个成功，不得重复签发");
    }

    @Test
    void concurrentRevokeIsIdempotentAndConsistent() throws Exception {
        TokenPair pair = tokenService.issue("alice");
        int threads = 8;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<?>> futures = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            futures.add(pool.submit(() -> {
                start.await();
                tokenService.revoke(pair.accessToken());
                return null;
            }));
        }
        start.countDown();
        for (var f : futures) {
            f.get();
        }
        pool.shutdown();
        log.info("input={} concurrent revokes, validate present={}",
                threads, tokenService.validate(pair.accessToken()).isPresent());
        assertFalse(tokenService.validate(pair.accessToken()).isPresent(),
                "并发撤销后令牌必须一致地不可再用");
    }

    @Test
    void revokeAllForUserKillsAccessAndRefresh() {
        TokenPair p1 = tokenService.issue("bob");
        TokenPair p2 = tokenService.issue("bob");
        tokenService.revokeAllForUser("bob");
        log.info("input=revokeAllForUser(bob): p1 valid={} p2 valid={} refresh valid={}",
                tokenService.validate(p1.accessToken()).isPresent(),
                tokenService.validate(p2.accessToken()).isPresent(),
                tokenService.refresh(p1.refreshToken()).isPresent());
        assertFalse(tokenService.validate(p1.accessToken()).isPresent());
        assertFalse(tokenService.validate(p2.accessToken()).isPresent());
        assertFalse(tokenService.refresh(p1.refreshToken()).isPresent());
    }

    @Test
    void otherUsersTokensUnaffectedByRevokeAll() {
        TokenPair alicePair = tokenService.issue("alice");
        tokenService.revokeAllForUser("bob");
        log.info("input=revokeAllForUser(bob); alice token valid={}",
                tokenService.validate(alicePair.accessToken()).isPresent());
        assertTrue(tokenService.validate(alicePair.accessToken()).isPresent(),
                "撤销不得波及其他用户（权限状态不得回退/错乱）");
    }
}
