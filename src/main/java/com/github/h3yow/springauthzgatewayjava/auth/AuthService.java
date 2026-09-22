package com.github.h3yow.springauthzgatewayjava.auth;

import com.github.h3yow.springauthzgatewayjava.auth.session.SessionRecord;
import com.github.h3yow.springauthzgatewayjava.auth.session.SessionService;
import com.github.h3yow.springauthzgatewayjava.util.Masking;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * 登录/登出编排：
 * 1. 锁定检查（锁定期间即使凭据正确也拒绝）；
 * 2. 账号状态检查（停用、凭据过期）；
 * 3. 口令校验（账号不存在与口令错误统一为 INVALID_CREDENTIALS，不泄露账号存在性）；
 * 4. 成功则清除失败计数并签发会话。
 * 同一用户名的登录按用户级锁串行化，保证并发登录结果一致。
 */
@Service
public class AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthService.class);

    public record LoginOutcome(boolean success, LoginFailureReason failureReason,
                               String sessionId, String csrfToken) {

        static LoginOutcome ok(String sessionId, String csrfToken) {
            return new LoginOutcome(true, null, sessionId, csrfToken);
        }

        static LoginOutcome fail(LoginFailureReason reason) {
            return new LoginOutcome(false, reason, null, null);
        }
    }

    private final UserStore userStore;
    private final PasswordService passwordService;
    private final LoginRateLimiter rateLimiter;
    private final SessionService sessionService;
    private final Map<String, Object> userLocks = new ConcurrentHashMap<>();

    public AuthService(UserStore userStore, PasswordService passwordService,
                       LoginRateLimiter rateLimiter, SessionService sessionService) {
        this.userStore = userStore;
        this.passwordService = passwordService;
        this.rateLimiter = rateLimiter;
        this.sessionService = sessionService;
    }

    public LoginOutcome login(String username, String rawPassword) {
        if (username == null || rawPassword == null) {
            return LoginOutcome.fail(LoginFailureReason.INVALID_CREDENTIALS);
        }
        Object lock = userLocks.computeIfAbsent(username, k -> new Object());
        synchronized (lock) {
            return doLogin(username, rawPassword);
        }
    }

    private LoginOutcome doLogin(String username, String rawPassword) {
        if (rateLimiter.isLocked(username)) {
            log.info("login rejected: locked user={} remaining={}",
                    username, rateLimiter.remainingLock(username));
            return LoginOutcome.fail(LoginFailureReason.ACCOUNT_LOCKED);
        }
        var userOpt = userStore.findByUsername(username);
        // 账号不存在与口令错误走同一路径、同一原因，且都执行一次散列比较以拉齐耗时
        String hashToCheck = userOpt.map(AuthUser::passwordHash)
                .orElseGet(() -> passwordService.hash("dummy-password-for-timing"));
        boolean passwordOk = passwordService.matches(rawPassword, hashToCheck);
        if (userOpt.isEmpty() || !passwordOk) {
            rateLimiter.onFailure(username);
            log.info("login failed: invalid credentials user={}", username);
            return LoginOutcome.fail(LoginFailureReason.INVALID_CREDENTIALS);
        }
        AuthUser user = userOpt.get();
        if (!user.enabled()) {
            rateLimiter.onFailure(username);
            log.info("login failed: disabled user={}", username);
            return LoginOutcome.fail(LoginFailureReason.ACCOUNT_DISABLED);
        }
        if (user.credentialsExpired()) {
            rateLimiter.onFailure(username);
            log.info("login failed: credentials expired user={}", username);
            return LoginOutcome.fail(LoginFailureReason.CREDENTIALS_EXPIRED);
        }
        rateLimiter.onSuccess(username);
        SessionRecord session = sessionService.create(username);
        log.info("login success user={} session={}", username, Masking.prefix(session.sessionId()));
        return LoginOutcome.ok(session.sessionId(), session.csrfToken());
    }

    public void logout(String sessionId) {
        sessionService.invalidate(sessionId);
    }
}
