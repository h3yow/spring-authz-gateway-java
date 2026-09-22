package com.github.h3yow.springauthzgatewayjava.auth;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * 口令散列与校验：PBKDF2（每口令随机盐），绝不保存或输出明文。
 */
@Component
public class PasswordService {

    private final PasswordEncoder encoder = Pbkdf2PasswordEncoder.defaultsForSpringSecurity_v5_8();

    public String hash(String rawPassword) {
        if (rawPassword == null || rawPassword.isEmpty()) {
            throw new IllegalArgumentException("raw password must not be empty");
        }
        return encoder.encode(rawPassword);
    }

    public boolean matches(String rawPassword, String storedHash) {
        if (rawPassword == null || storedHash == null || storedHash.isBlank()) {
            return false;
        }
        try {
            return encoder.matches(rawPassword, storedHash);
        } catch (IllegalArgumentException e) {
            // 存储散列损坏视为不匹配，而非异常放行
            return false;
        }
    }
}
