package com.github.h3yow.springauthzgatewayjava.auth;

import java.time.Instant;
import java.util.Set;

/** 账号实体：仅存口令散列，不存明文。 */
public record UserAccount(
        String username,
        String passwordHash,
        Set<Role> roles,
        AccountStatus status,
        Instant credentialsExpireAt) {

    public boolean credentialsExpired(Instant now) {
        return credentialsExpireAt != null && now.isAfter(credentialsExpireAt);
    }
}
