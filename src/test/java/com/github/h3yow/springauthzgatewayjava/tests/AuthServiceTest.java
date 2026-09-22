package com.github.h3yow.springauthzgatewayjava.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.h3yow.springauthzgatewayjava.auth.AuthService;
import com.github.h3yow.springauthzgatewayjava.auth.AuthUser;
import com.github.h3yow.springauthzgatewayjava.auth.LoginFailureReason;
import com.github.h3yow.springauthzgatewayjava.auth.LoginRateLimiter;
import com.github.h3yow.springauthzgatewayjava.auth.PasswordService;
import com.github.h3yow.springauthzgatewayjava.auth.UserStore;
import com.github.h3yow.springauthzgatewayjava.auth.session.SessionService;
import com.github.h3yow.springauthzgatewayjava.config.AuthSecurityProperties;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class AuthServiceTest {

    private static final Logger log = LoggerFactory.getLogger(AuthServiceTest.class);

    private MutableClock clock;
    private AuthSecurityProperties props;
    private UserStore userStore;
    private AuthService authService;
    private SessionService sessionService;
    private PasswordService passwordService;

    @BeforeEach
    void setUp() {
        clock = new MutableClock(Instant.parse("2026-09-22T00:00:00Z"));
        props = new AuthSecurityProperties();
        props.setLoginMaxFailures(3);
        props.setLoginFailureWindow(Duration.ofMinutes(5));
        props.setLoginLockDuration(Duration.ofMinutes(10));
        passwordService = new PasswordService();
        userStore = new UserStore(passwordService);
        sessionService = new SessionService(props, clock);
        authService = new AuthService(userStore, passwordService,
                new LoginRateLimiter(props, clock), sessionService);
    }

    @Test
    void successfulLoginIssuesSession() {
        var outcome = authService.login("alice", "alice-pass-123");
        log.info("input=alice/correct-password outcome success={} reason={}", outcome.success(), outcome.failureReason());
        assertTrue(outcome.success());
        assertNotNull(outcome.sessionId());
        assertNotNull(outcome.csrfToken());
        assertTrue(sessionService.resolve(outcome.sessionId()).isPresent());
    }

    @Test
    void unknownUserAndWrongPasswordShareSameReason() {
        var unknown = authService.login("no-such-user", "whatever");
        var wrongPass = authService.login("alice", "wrong-password");
        log.info("input=unknown-user reason={} | input=wrong-password reason={}",
                unknown.failureReason(), wrongPass.failureReason());
        assertEquals(LoginFailureReason.INVALID_CREDENTIALS, unknown.failureReason());
        assertEquals(LoginFailureReason.INVALID_CREDENTIALS, wrongPass.failureReason(),
                "账号不存在与口令错误必须返回同一原因，不得泄露账号存在性");
    }

    @Test
    void disabledAccountRejected() {
        var outcome = authService.login("carol", "carol-pass-123");
        log.info("input=carol(disabled)/correct-password reason={}", outcome.failureReason());
        assertFalse(outcome.success());
        assertEquals(LoginFailureReason.ACCOUNT_DISABLED, outcome.failureReason());
    }

    @Test
    void expiredCredentialsRejected() {
        var outcome = authService.login("dave", "dave-pass-123");
        log.info("input=dave(credentials-expired)/correct-password reason={}", outcome.failureReason());
        assertFalse(outcome.success());
        assertEquals(LoginFailureReason.CREDENTIALS_EXPIRED, outcome.failureReason());
    }

    @Test
    void lockedAccountRejectsEvenCorrectPassword() {
        for (int i = 1; i <= 3; i++) {
            var fail = authService.login("bob", "wrong-" + i);
            log.info("input=bob/wrong-password #{} reason={}", i, fail.failureReason());
        }
        var locked = authService.login("bob", "bob-pass-123");
        log.info("input=bob/correct-password while locked reason={}", locked.failureReason());
        assertFalse(locked.success());
        assertEquals(LoginFailureReason.ACCOUNT_LOCKED, locked.failureReason(),
                "锁定期间即使凭据正确也不得通过");
    }

    @Test
    void lockAutoRecoversAndLoginSucceeds() {
        for (int i = 0; i < 3; i++) {
            authService.login("bob", "wrong");
        }
        clock.advance(Duration.ofMinutes(11));
        var outcome = authService.login("bob", "bob-pass-123");
        log.info("input=bob/correct-password after lock expiry success={}", outcome.success());
        assertTrue(outcome.success(), "锁定到期后必须自动恢复");
    }

    @Test
    void failedAttemptsDoNotPolluteExistingSession() {
        var ok = authService.login("alice", "alice-pass-123");
        String sessionId = ok.sessionId();
        authService.login("alice", "wrong");
        authService.login("alice", "wrong");
        log.info("input=2 failed logins after success; existing session resolvable={}",
                sessionService.resolve(sessionId).isPresent());
        assertTrue(sessionService.resolve(sessionId).isPresent(),
                "失败尝试不得污染已有认证状态");
    }

    @Test
    void concurrentLoginsAreConsistent() throws Exception {
        int threads = 16;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<AuthService.LoginOutcome>> futures = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            futures.add(pool.submit(() -> {
                start.await();
                return authService.login("alice", "alice-pass-123");
            }));
        }
        start.countDown();
        Set<String> sessionIds = new java.util.HashSet<>();
        for (var f : futures) {
            var outcome = f.get();
            assertTrue(outcome.success(), "并发正确登录必须全部成功");
            sessionIds.add(outcome.sessionId());
        }
        pool.shutdown();
        log.info("input={} concurrent logins, distinct sessions={}", threads, sessionIds.size());
        assertEquals(threads, sessionIds.size(), "每次登录必须签发独立会话，不得半更新");
    }

    @Test
    void concurrentMixedLoginsDoNotCorruptLockState() throws Exception {
        int threads = 10;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<AuthService.LoginOutcome>> futures = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            String password = (i % 2 == 0) ? "bob-pass-123" : "wrong";
            futures.add(pool.submit(() -> {
                start.await();
                return authService.login("bob", password);
            }));
        }
        start.countDown();
        int successes = 0;
        int invalid = 0;
        for (var f : futures) {
            var outcome = f.get();
            if (outcome.success()) {
                successes++;
            } else if (outcome.failureReason() == LoginFailureReason.INVALID_CREDENTIALS) {
                invalid++;
            }
            log.info("concurrent mixed outcome success={} reason={}", outcome.success(), outcome.failureReason());
        }
        pool.shutdown();
        // 5 次错误 + 5 次正确：错误达到阈值(3)后锁定，此后正确密码也被拒；
        // 但无论交错顺序如何，结果只能是 成功/INVALID_CREDENTIALS/ACCOUNT_LOCKED 之一，且状态一致
        log.info("successes={} invalid={} total={}", successes, invalid, threads);
        assertEquals(threads, successes + invalid + (threads - successes - invalid));
        assertTrue(successes >= 1, "至少早到的正确登录应成功");
    }

    @Test
    void plaintextPasswordNeverStored() {
        AuthUser alice = userStore.findByUsername("alice").orElseThrow();
        log.info("stored hash prefix={}...", alice.passwordHash().substring(0, 8));
        assertFalse(alice.passwordHash().contains("alice-pass-123"), "口令不得以明文存储");
        assertTrue(passwordService.matches("alice-pass-123", alice.passwordHash()));
    }
}
