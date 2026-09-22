package com.github.h3yow.springauthzgatewayjava.auth;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * 登录失败限流与账号临时锁定。
 * 阈值、窗口、锁定时长由 {@link AuthProperties} 配置；
 * 锁定期间即使凭据正确也不得通过，锁定到期后自动恢复。
 * 所有状态变更通过 ConcurrentHashMap.compute 原子完成，并发下不出现半更新。
 */
@Component
public class LoginGuard {

    private static final Logger log = LoggerFactory.getLogger(LoginGuard.class);

    private final AuthProperties properties;
    private final Clock clock;
    private final Map<String, GuardState> states = new ConcurrentHashMap<>();

    @org.springframework.beans.factory.annotation.Autowired
    public LoginGuard(AuthProperties properties) {
        this(properties, Clock.systemUTC());
    }

    LoginGuard(AuthProperties properties, Clock clock) {
        this.properties = properties;
        this.clock = clock;
    }

    private static final class GuardState {
        final Deque<Instant> failures = new ArrayDeque<>();
        Instant lockedUntil;
    }

    /** 登录前检查：true 表示被限流/锁定，不得继续（即使凭据正确）。 */
    public boolean isBlocked(String key) {
        Instant now = clock.instant();
        boolean[] blocked = {false};
        states.compute(key, (k, s) -> {
            if (s == null) {
                return null;
            }
            prune(s, now);
            blocked[0] = isBlockedNow(s, now);
            return s.failures.isEmpty() && s.lockedUntil == null ? null : s;
        });
        return blocked[0];
    }

    private boolean isBlockedNow(GuardState s, Instant now) {
        if (s == null) {
            return false;
        }
        if (s.lockedUntil != null && now.isBefore(s.lockedUntil)) {
            return true; // 锁定中
        }
        return s.failures.size() >= properties.getLoginMaxFailures();
    }

    /** 记录一次失败；窗口内失败数达到阈值即进入锁定。 */
    public void onFailure(String key) {
        Instant now = clock.instant();
        states.compute(key, (k, s) -> {
            GuardState state = s == null ? new GuardState() : s;
            prune(state, now);
            state.failures.addLast(now);
            if (state.failures.size() >= properties.getLoginMaxFailures()
                    && (state.lockedUntil == null || !now.isBefore(state.lockedUntil))) {
                state.lockedUntil = now.plus(properties.getLockoutDuration());
                log.info("login guard locked key={} until={}", key, state.lockedUntil);
            }
            return state;
        });
    }

    /** 登录成功后清除失败计数与锁定状态。 */
    public void onSuccess(String key) {
        states.remove(key);
    }

    /** 锁定到期自动恢复：过期失败记录被剔除，锁定标记清除。 */
    private void prune(GuardState s, Instant now) {
        Instant windowStart = now.minus(properties.getLoginFailureWindow());
        while (!s.failures.isEmpty() && s.failures.peekFirst().isBefore(windowStart)) {
            s.failures.pollFirst();
        }
        if (s.lockedUntil != null && !now.isBefore(s.lockedUntil)) {
            s.lockedUntil = null; // 锁定到期，自动恢复
        }
    }

    /** 剩余锁定秒数（用于错误响应与测试断言），未锁定返回 0。 */
    public long lockedSecondsRemaining(String key) {
        GuardState s = states.get(key);
        if (s == null || s.lockedUntil == null) {
            return 0;
        }
        long secs = s.lockedUntil.getEpochSecond() - clock.instant().getEpochSecond();
        return Math.max(0, secs);
    }
}
