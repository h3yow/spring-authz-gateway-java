package com.github.h3yow.springauthzgatewayjava.auth;

import static org.junit.jupiter.api.Assertions.*;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 并发撤销收敛：单个撤销与"撤销其余全部"近乎同时发生、同一凭据被并发撤销多次时，
 * 最终必须收敛到一致结果——应失效的凭据无一可用，已撤销凭据绝不复活。
 */
class CredentialConcurrencyTest {

    private static final Logger log = LoggerFactory.getLogger(CredentialConcurrencyTest.class);

    private SessionService sessions;
    private TokenService tokens;
    private CredentialService credentials;

    @BeforeEach
    void setUp() {
        AuthProperties props = new AuthProperties();
        props.setSessionIdleTtl(Duration.ofMinutes(30));
        props.setSessionMaxTtl(Duration.ofHours(12));
        props.setAccessTokenTtl(Duration.ofMinutes(10));
        props.setRefreshTokenTtl(Duration.ofHours(12));
        sessions = new SessionService(props);
        tokens = new TokenService(props);
        credentials = new CredentialService(sessions, tokens);
    }

    @Test
    void concurrentRepeatedSingleRevokeSucceedsExactlyOnce() throws InterruptedException {
        int n = 32;
        List<SessionRecord> sessionRecords = new ArrayList<>();
        List<TokenService.TokenPair> tokenPairs = new ArrayList<>();
        List<String> tokenJtis = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            sessionRecords.add(sessions.create("alice", Set.of(Role.USER), "c" + i));
            TokenService.TokenPair pair = tokens.issue("alice", Set.of(Role.USER), "c" + i);
            tokenPairs.add(pair);
            tokenJtis.add(tokens.jtiOf(pair.accessToken()));
        }
        int threadsPerCredential = 8;
        ExecutorService pool = Executors.newFixedThreadPool(16);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger trueRevokes = new AtomicInteger();
        // 每个凭据被多个线程并发撤销（会话句柄 + 令牌 jti 都覆盖）
        for (int i = 0; i < n; i++) {
            final String sessionRef = sessionRecords.get(i).credentialId();
            final String tokenRef = tokenJtis.get(i);
            for (int t = 0; t < threadsPerCredential; t++) {
                pool.submit(() -> {
                    try {
                        start.await();
                        if (credentials.revokeCredential("alice", sessionRef)) {
                            trueRevokes.incrementAndGet();
                        }
                        if (credentials.revokeCredential("alice", tokenRef)) {
                            trueRevokes.incrementAndGet();
                        }
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                });
            }
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));

        assertEquals(2 * n, trueRevokes.get(),
                "无论并发多少次，每个凭据只能被成功撤销一次，结果必须收敛");
        // 全部凭据失效，且再撤销均为 false
        for (int i = 0; i < n; i++) {
            assertTrue(sessions.find(sessionRecords.get(i).sessionId()).isEmpty());
            assertTrue(tokens.verifyAccessToken(tokenPairs.get(i).accessToken()).isEmpty());
            assertFalse(credentials.revokeCredential("alice", sessionRecords.get(i).credentialId()));
            assertFalse(credentials.revokeCredential("alice", tokenJtis.get(i)));
        }
        log.info("input: {} credentials x {} concurrent revokes -> exactly {} effective revokes",
                2 * n, threadsPerCredential, trueRevokes.get());
    }

    @Test
    void singleRevokeAndRevokeOthersConvergeWithoutReactivation() throws InterruptedException {
        int n = 40;
        List<SessionRecord> sessionRecords = new ArrayList<>();
        List<TokenService.TokenPair> tokenPairs = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            sessionRecords.add(sessions.create("alice", Set.of(Role.USER), "c" + i));
            tokenPairs.add(tokens.issue("alice", Set.of(Role.USER), "c" + i));
        }
        SessionRecord keep = sessions.create("alice", Set.of(Role.USER), "client-keep");

        ExecutorService pool = Executors.newFixedThreadPool(16);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger errors = new AtomicInteger();

        // 组一：对每个非保留凭据并发执行"撤销单个"
        for (int i = 0; i < n; i++) {
            final int idx = i;
            pool.submit(() -> {
                try {
                    start.await();
                    credentials.revokeCredential("alice", sessionRecords.get(idx).credentialId());
                    credentials.revokeCredential("alice", tokens.jtiOf(tokenPairs.get(idx).accessToken()));
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } catch (RuntimeException e) {
                    errors.incrementAndGet();
                }
            });
        }
        // 组二：与组一近乎同时，反复执行"撤销其余全部（保留当前会话）"
        for (int r = 0; r < 16; r++) {
            pool.submit(() -> {
                try {
                    start.await();
                    for (int k = 0; k < 25; k++) {
                        credentials.revokeOthers("alice", CredentialKind.SESSION, keep.credentialId());
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } catch (RuntimeException e) {
                    errors.incrementAndGet();
                }
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));
        assertEquals(0, errors.get(), "并发撤销不得抛出异常");

        // 收敛断言一：除保留会话外，无一凭据可用
        for (int i = 0; i < n; i++) {
            assertTrue(sessions.find(sessionRecords.get(i).sessionId()).isEmpty(),
                    "并发收敛后该会话必须失效");
            assertTrue(tokens.verifyAccessToken(tokenPairs.get(i).accessToken()).isEmpty(),
                    "并发收敛后该令牌必须失效");
        }
        assertTrue(sessions.find(keep.sessionId()).isPresent(), "当前会话在整个过程后仍必须可用");

        // 收敛断言二：稳定期反复校验，不得有任何凭据复活
        ExecutorService verifiers = Executors.newFixedThreadPool(16);
        CountDownLatch verifyStart = new CountDownLatch(1);
        AtomicInteger acceptedAfterConvergence = new AtomicInteger();
        for (int v = 0; v < 16; v++) {
            verifiers.submit(() -> {
                try {
                    verifyStart.await();
                    for (int k = 0; k < 100; k++) {
                        for (int i = 0; i < n; i++) {
                            if (sessions.find(sessionRecords.get(i).sessionId()).isPresent()) {
                                acceptedAfterConvergence.incrementAndGet();
                            }
                            if (tokens.verifyAccessToken(tokenPairs.get(i).accessToken()).isPresent()) {
                                acceptedAfterConvergence.incrementAndGet();
                            }
                        }
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        verifyStart.countDown();
        verifiers.shutdown();
        assertTrue(verifiers.awaitTermination(30, TimeUnit.SECONDS));
        assertEquals(0, acceptedAfterConvergence.get(), "已撤销凭据在收敛后不得复活");

        // 收敛断言三：最终视图与再次操作幂等
        assertEquals(1, credentials.listActive("alice").size(), "最终只剩保留的当前凭据");
        assertEquals(0, credentials.revokeOthers("alice", CredentialKind.SESSION, keep.credentialId()));
        log.info("input: concurrent single+others revoke -> converged, residual accepts={}, activeAfter={}",
                acceptedAfterConvergence.get(), credentials.listActive("alice").size());
    }

    @Test
    void revokeOthersFromTokenKindAndFromSessionKindDoNotReviveEachOther() throws InterruptedException {
        // 两条"撤销其余全部"路径（分别声称当前凭据是会话 / 是令牌）并发执行后，
        // 无论保留哪个，先前已撤销的凭据都不得复活
        SessionRecord s1 = sessions.create("alice", Set.of(Role.USER), "a");
        TokenService.TokenPair t1 = tokens.issue("alice", Set.of(Role.USER), "b");

        // 先撤销 s1，随后另一路径以 t1 为当前凭据执行撤销其余（kind=TOKEN），s1 不得复活
        assertTrue(credentials.revokeCredential("alice", s1.credentialId()));
        credentials.revokeOthers("alice", CredentialKind.ACCESS_TOKEN, tokens.jtiOf(t1.accessToken()));
        assertTrue(sessions.find(s1.sessionId()).isEmpty());
        assertTrue(tokens.verifyAccessToken(t1.accessToken()).isPresent());

        // 再切回以（已被撤销的）s1 声称"当前凭据"执行撤销其余：保留参数无效，t1 应被撤销且 s1 不复活
        int count = credentials.revokeOthers("alice", CredentialKind.SESSION, s1.credentialId());
        log.info("input: revoke-others with already-revoked keep-ref -> count={}", count);
        assertTrue(sessions.find(s1.sessionId()).isEmpty(), "已撤销凭据不得因成为保留项而复活");
        assertTrue(tokens.verifyAccessToken(t1.accessToken()).isEmpty(), "无效保留项不得保护任何令牌");
    }
}
