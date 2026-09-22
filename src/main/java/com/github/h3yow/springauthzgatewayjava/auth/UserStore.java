package com.github.h3yow.springauthzgatewayjava.auth;

import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Component;

/**
 * 本地内存账号仓库：预置演示账号（口令仅以散列保存），不依赖任何外部服务。
 * 演示口令仅用于本地验证，见 README。
 */
@Component
public class UserStore {

    private final Map<String, AuthUser> users = new ConcurrentHashMap<>();

    public UserStore(PasswordService passwordService) {
        // 预置账号：alice(ADMIN+USER)、bob(USER)、carol(停用)、dave(凭据过期)
        save(new AuthUser("alice", passwordService.hash("alice-pass-123"),
                Set.of("ADMIN", "USER"), true, false));
        save(new AuthUser("bob", passwordService.hash("bob-pass-123"),
                Set.of("USER"), true, false));
        save(new AuthUser("carol", passwordService.hash("carol-pass-123"),
                Set.of("USER"), false, false));
        save(new AuthUser("dave", passwordService.hash("dave-pass-123"),
                Set.of("USER"), true, true));
    }

    public Optional<AuthUser> findByUsername(String username) {
        if (username == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(users.get(username));
    }

    /** 测试或管理用途的账号写入（口令必须已散列）。 */
    public void save(AuthUser user) {
        users.put(user.username(), user);
    }
}
