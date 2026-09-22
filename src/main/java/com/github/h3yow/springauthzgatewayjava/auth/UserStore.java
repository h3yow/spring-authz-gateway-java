package com.github.h3yow.springauthzgatewayjava.auth;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * 内存账号仓库：本地可运行，不依赖外部服务与真实凭据。
 * 演示口令仅以散列形式在启动时计算并保存，明文不出现在存储与日志中。
 */
@Component
public class UserStore {

    private static final Logger log = LoggerFactory.getLogger(UserStore.class);

    private final Map<String, UserAccount> accounts = new ConcurrentHashMap<>();

    public UserStore(PasswordHasher hasher) {
        // 仅用于本地演示的账号；口令明文仅出现在此处初始化瞬间，存储与日志中均为散列。
        register(hasher, "alice", "alice-pass-123".toCharArray(), Set.of(Role.USER),
                AccountStatus.ACTIVE, Instant.now().plus(180, ChronoUnit.DAYS));
        register(hasher, "admin", "admin-pass-123".toCharArray(), Set.of(Role.USER, Role.ADMIN),
                AccountStatus.ACTIVE, Instant.now().plus(180, ChronoUnit.DAYS));
        register(hasher, "disabled-bob", "bob-pass-123".toCharArray(), Set.of(Role.USER),
                AccountStatus.DISABLED, Instant.now().plus(180, ChronoUnit.DAYS));
        register(hasher, "expired-carol", "carol-pass-123".toCharArray(), Set.of(Role.USER),
                AccountStatus.ACTIVE, Instant.now().minus(1, ChronoUnit.DAYS));
        log.info("user store initialized, accounts={}", accounts.keySet());
    }

    private void register(PasswordHasher hasher, String username, char[] password,
                          Set<Role> roles, AccountStatus status, Instant credentialsExpireAt) {
        accounts.put(username, new UserAccount(username, hasher.hash(password), roles, status, credentialsExpireAt));
    }

    public Optional<UserAccount> findByUsername(String username) {
        return Optional.ofNullable(accounts.get(username));
    }
}
