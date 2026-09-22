package com.github.h3yow.springauthzgatewayjava.auth;

import com.github.h3yow.springauthzgatewayjava.config.AuthSecurityProperties;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * 登录失败限流与临时锁定：
 * 滑动窗口内失败次数达到阈值即锁定，锁定期间即使凭据正确也拒绝，到期自动恢复。
 * 阈值、窗口与锁定时长均可配置。按 key（用户名）独立统计，线程安全。
 */
@Component
public class LoginRateLimiter {

    private static final Logger log = LoggerFactory.getLogger(LoginRateLimiter.class);

    private static final class State {
        final Deque<Instant> failures = new ArrayDeque<>();
        Instant lockedUntil;
    }

    private final Map<String, State> states = new ConcurrentHashMap<>();
    private final AuthSecurityProperties props;
    private final Clock clock;

    public LoginRateLimiter(AuthSecurityProperties props, Clock clock) {
        this.props = props;
        this.clock = clock;
    }

    public boolean isLocked(String key) {
        State state = states.get(key);
        if (state == null) {
            return false;
        }
        synchronized (state) {
            return state.lockedUntil != null && clock.instant().isBefore(state.lockedUntil);
        }
    }

    public Duration remainingLock(String key) {
        State state = states.get(key);
        if (state == null) {
            return Duration.ZERO;
        }
        synchronized (state) {
            if (state.lockedUntil == null) {
                return Duration.ZERO;
            }
            Duration remaining = Duration.between(clock.instant(), state.lockedUntil);
            return remaining.isNegative() ? Duration.ZERO : remaining;
        }
    }

    /** 记录一次失败；达到阈值即进入锁定。 */
    public void onFailure(String key) {
        State state = states.computeIfAbsent(key, k -> new State());
        synchronized (state) {
            Instant now = clock.instant();
            prune(state, now);
            state.failures.addLast(now);
            if (state.failures.size() >= props.getLoginMaxFailures()) {
                state.lockedUntil = now.plus(props.getLoginLockDuration());
                state.failures.clear();
                log.info("login lock triggered key={} lockedFor={}", key, props.getLoginLockDuration());
            }
        }
    }

    /** 登录成功：清除该 key 的失败计数与锁定状态。 */
    public void onSuccess(String key) {
        State state = states.get(key);
        if (state == null) {
            return;
        }
        synchronized (state) {
            state.failures.clear();
            state.lockedUntil = null;
        }
    }

    private void prune(State state, Instant now) {
        Instant cutoff = now.minus(props.getLoginFailureWindow());
        while (!state.failures.isEmpty() && state.failures.peekFirst().isBefore(cutoff)) {
            state.failures.pollFirst();
        }
    }
}
