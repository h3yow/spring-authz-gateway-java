package com.github.h3yow.springauthzgatewayjava.auth;

import java.time.Clock;
import java.time.Instant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * 登录/登出编排。
 *
 * <p>失败原因在内部以 {@link AuthFailureReason} 区分并记入日志（便于排查），
 * 但对外统一表现为"无效凭据"，不泄露账号是否存在。
 * 对不存在的账号同样执行一次口令散列校验，使响应时序与真实账号一致。
 *
 * <p>登录成功同时签发有状态会话与无状态令牌对，两种访问方式并存。
 */
@Service
public class AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthService.class);

    /** 对不存在账号执行的哑校验目标，抹平时序差异。 */
    private static final String DUMMY_HASH =
            "pbkdf2$60000$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    private final UserStore userStore;
    private final PasswordHasher hasher;
    private final LoginGuard loginGuard;
    private final SessionService sessionService;
    private final TokenService tokenService;
    private final Clock clock;

    public AuthService(UserStore userStore, PasswordHasher hasher, LoginGuard loginGuard,
                       SessionService sessionService, TokenService tokenService) {
        this.userStore = userStore;
        this.hasher = hasher;
        this.loginGuard = loginGuard;
        this.sessionService = sessionService;
        this.tokenService = tokenService;
        this.clock = Clock.systemUTC();
    }

    /**
     * @param username  登录名
     * @param password  口令（使用后由调用方清零）
     * @param clientKey 限流维度（如客户端 IP）
     */
    public AuthResult login(String username, char[] password, String clientKey) {
        String guardKey = username + "|" + clientKey;
        // 1. 限流/锁定检查优先：锁定期间即使凭据正确也不得通过
        if (loginGuard.isBlocked(guardKey)) {
            log.info("login blocked user={} reason={}", username, AuthFailureReason.ACCOUNT_LOCKED);
            return AuthResult.fail(AuthFailureReason.ACCOUNT_LOCKED);
        }

        var account = userStore.findByUsername(username);
        // 2. 口令校验（账号不存在时用哑散列，时序一致）
        boolean passwordOk = hasher.verify(password,
                account.map(UserAccount::passwordHash).orElse(DUMMY_HASH));

        AuthFailureReason failure = classify(account.orElse(null), passwordOk);
        if (failure != null) {
            loginGuard.onFailure(guardKey);
            log.info("login failed user={} reason={}", username, failure);
            return AuthResult.fail(failure);
        }

        // 3. 成功：清除限流计数，签发会话与令牌
        loginGuard.onSuccess(guardKey);
        UserAccount user = account.orElseThrow();
        SessionRecord session = sessionService.create(user.username(), user.roles());
        TokenService.TokenPair tokens = tokenService.issue(user.username(), user.roles());
        log.info("login success user={} roles={}", username, user.roles());
        return AuthResult.ok(session, tokens.accessToken(), tokens.refreshToken());
    }

    /** 内部可区分的失败分类；对外统一映射为无效凭据。 */
    private AuthFailureReason classify(UserAccount account, boolean passwordOk) {
        if (account == null) {
            return AuthFailureReason.ACCOUNT_NOT_FOUND;
        }
        if (account.status() == AccountStatus.DISABLED) {
            return AuthFailureReason.ACCOUNT_DISABLED;
        }
        if (account.credentialsExpired(Instant.now(clock))) {
            return AuthFailureReason.CREDENTIALS_EXPIRED;
        }
        if (!passwordOk) {
            return AuthFailureReason.BAD_PASSWORD;
        }
        return null;
    }

    /** 登出：撤销会话并撤销该用户全部令牌，立即生效。 */
    public void logout(String sessionId, String username) {
        sessionService.revoke(sessionId);
        if (username != null) {
            tokenService.revokeAllForUser(username);
        }
    }
}
