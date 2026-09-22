package com.github.h3yow.springauthzgatewayjava.auth;

import static org.junit.jupiter.api.Assertions.*;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class AuthServiceTest {

    private static final Logger log = LoggerFactory.getLogger(AuthServiceTest.class);

    private PasswordHasher hasher;
    private UserStore store;
    private AuthService authService;
    private SessionService sessionService;
    private TokenService tokenService;

    @BeforeEach
    void setUp() {
        hasher = new PasswordHasher();
        AuthProperties props = new AuthProperties();
        props.setLoginMaxFailures(3);
        props.setLoginFailureWindow(Duration.ofMinutes(5));
        props.setLockoutDuration(Duration.ofMinutes(10));
        store = new UserStore(hasher);
        sessionService = new SessionService(props);
        tokenService = new TokenService(props);
        authService = new AuthService(store, hasher, new LoginGuard(props), sessionService, tokenService);
    }

    private AuthResult login(String user, String password) {
        return authService.login(user, password.toCharArray(), "127.0.0.1");
    }

    @Test
    void successfulLoginIssuesSessionAndTokens() {
        AuthResult r = login("alice", "alice-pass-123");
        log.info("input: alice + correct password -> success={}", r.success());
        assertTrue(r.success());
        assertNotNull(r.session());
        assertNotNull(r.accessToken());
        assertNotNull(r.refreshToken());
        assertTrue(sessionService.find(r.session().sessionId()).isPresent());
        assertTrue(tokenService.verifyAccessToken(r.accessToken()).isPresent());
    }

    @Test
    void failureReasonsAreClassifiedInternally() {
        log.info("input: nonexistent / disabled / expired / bad-password accounts");
        assertEquals(AuthFailureReason.ACCOUNT_NOT_FOUND, login("nosuch", "x").failureReason());
        assertEquals(AuthFailureReason.ACCOUNT_DISABLED, login("disabled-bob", "bob-pass-123").failureReason());
        assertEquals(AuthFailureReason.CREDENTIALS_EXPIRED, login("expired-carol", "carol-pass-123").failureReason());
        assertEquals(AuthFailureReason.BAD_PASSWORD, login("alice", "wrong").failureReason());
        log.info("decision: four distinct internal reasons, all distinguishable");
    }

    @Test
    void disabledAndExpiredNeverPassEvenWithCorrectPassword() {
        log.info("input: correct passwords for disabled-bob and expired-carol");
        assertFalse(login("disabled-bob", "bob-pass-123").success(), "停用账号不得通过");
        assertFalse(login("expired-carol", "carol-pass-123").success(), "过期凭据不得通过");
    }

    @Test
    void lockedAccountRejectsEvenCorrectPassword() {
        log.info("input: 3 bad passwords (threshold=3) then correct password");
        login("alice", "wrong1");
        login("alice", "wrong2");
        login("alice", "wrong3");
        AuthResult r = login("alice", "alice-pass-123");
        log.info("decision: success={} reason={}", r.success(), r.failureReason());
        assertFalse(r.success(), "锁定期间即使凭据正确也不得通过");
        assertEquals(AuthFailureReason.ACCOUNT_LOCKED, r.failureReason());
    }

    @Test
    void logoutRevokesSessionAndTokensImmediately() {
        AuthResult r = login("alice", "alice-pass-123");
        authService.logout(r.session().sessionId(), "alice");
        log.info("input: logout then re-verify session and access token");
        assertTrue(sessionService.find(r.session().sessionId()).isEmpty(), "会话撤销后立即失效");
        assertTrue(tokenService.verifyAccessToken(r.accessToken()).isEmpty(), "令牌撤销后立即失效");
        assertTrue(tokenService.refresh(r.refreshToken()).isEmpty());
    }

    @Test
    void concurrentLoginsYieldDistinctValidCredentials() throws InterruptedException {
        int threads = 16;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        Set<String> sessionIds = ConcurrentHashMap.newKeySet();
        Set<String> accessTokens = ConcurrentHashMap.newKeySet();
        Set<String> failures = ConcurrentHashMap.newKeySet();
        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    AuthResult r = authService.login("admin", "admin-pass-123".toCharArray(), "10.1.1.1");
                    if (r.success()) {
                        sessionIds.add(r.session().sessionId());
                        accessTokens.add(r.accessToken());
                    } else {
                        failures.add(String.valueOf(r.failureReason()));
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));
        log.info("input: {} concurrent logins for admin -> distinctSessions={} distinctTokens={} failures={}",
                threads, sessionIds.size(), accessTokens.size(), failures);
        assertEquals(threads, sessionIds.size(), "每次登录必须签发独立会话，不得重复或丢失");
        assertEquals(threads, accessTokens.size(), "每次登录必须签发独立令牌");
        assertTrue(failures.isEmpty(), "并发登录不得出现失败");
        // 全部凭据立即可用
        for (String t : accessTokens) {
            assertTrue(tokenService.verifyAccessToken(t).isPresent());
        }
    }

    @Test
    void failedLoginDoesNotPolluteExistingAuthState() {
        AuthResult good = login("alice", "alice-pass-123");
        log.info("input: valid login, then failed logins, then re-check original credentials");
        login("alice", "wrong");
        login("nosuch", "x");
        assertTrue(sessionService.find(good.session().sessionId()).isPresent(),
                "失败登录不得污染已有会话");
        assertTrue(tokenService.verifyAccessToken(good.accessToken()).isPresent(),
                "失败登录不得污染已有令牌");
    }
}
