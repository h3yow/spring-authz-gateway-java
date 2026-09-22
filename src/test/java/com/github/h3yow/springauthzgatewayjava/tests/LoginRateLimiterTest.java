package com.github.h3yow.springauthzgatewayjava.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.h3yow.springauthzgatewayjava.auth.LoginRateLimiter;
import com.github.h3yow.springauthzgatewayjava.config.AuthSecurityProperties;
import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class LoginRateLimiterTest {

    private static final Logger log = LoggerFactory.getLogger(LoginRateLimiterTest.class);

    private MutableClock clock;
    private AuthSecurityProperties props;
    private LoginRateLimiter limiter;

    @BeforeEach
    void setUp() {
        clock = new MutableClock(Instant.parse("2026-09-22T00:00:00Z"));
        props = new AuthSecurityProperties();
        props.setLoginMaxFailures(3);
        props.setLoginFailureWindow(Duration.ofMinutes(5));
        props.setLoginLockDuration(Duration.ofMinutes(10));
        limiter = new LoginRateLimiter(props, clock);
    }

    @Test
    void locksAfterThresholdFailures() {
        String key = "alice";
        for (int i = 1; i <= 3; i++) {
            limiter.onFailure(key);
            log.info("input=failure #{} key={} locked={}", i, key, limiter.isLocked(key));
        }
        assertTrue(limiter.isLocked(key), "达到阈值后必须锁定");
        assertEquals(Duration.ofMinutes(10), limiter.remainingLock(key));
    }

    @Test
    void doesNotLockBelowThreshold() {
        limiter.onFailure("alice");
        limiter.onFailure("alice");
        log.info("input=2 failures (threshold=3) locked={}", limiter.isLocked("alice"));
        assertFalse(limiter.isLocked("alice"));
    }

    @Test
    void failuresOutsideWindowDoNotCount() {
        limiter.onFailure("alice");
        limiter.onFailure("alice");
        clock.advance(Duration.ofMinutes(6)); // 超出 5 分钟窗口
        limiter.onFailure("alice");
        log.info("input=2 old failures expired + 1 new, window={} locked={}",
                props.getLoginFailureWindow(), limiter.isLocked("alice"));
        assertFalse(limiter.isLocked("alice"), "窗口外的失败不应计入");
    }

    @Test
    void lockExpiresAutomatically() {
        for (int i = 0; i < 3; i++) {
            limiter.onFailure("alice");
        }
        assertTrue(limiter.isLocked("alice"));
        clock.advance(Duration.ofMinutes(11));
        log.info("input=advanced {} past lockDuration={} locked={}",
                Duration.ofMinutes(11), props.getLoginLockDuration(), limiter.isLocked("alice"));
        assertFalse(limiter.isLocked("alice"), "锁定到期后必须自动恢复");
    }

    @Test
    void successClearsFailureCount() {
        limiter.onFailure("alice");
        limiter.onFailure("alice");
        limiter.onSuccess("alice");
        limiter.onFailure("alice");
        limiter.onFailure("alice");
        log.info("input=2 failures, success, 2 failures (threshold=3) locked={}", limiter.isLocked("alice"));
        assertFalse(limiter.isLocked("alice"), "成功后计数必须清零");
    }

    @Test
    void keysAreIndependent() {
        for (int i = 0; i < 3; i++) {
            limiter.onFailure("alice");
        }
        log.info("input=alice locked, checking bob locked={}", limiter.isLocked("bob"));
        assertFalse(limiter.isLocked("bob"), "不同账号的限流互不影响");
    }
}
