package com.github.h3yow.springauthzgatewayjava.util;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * 敏感字段脱敏：日志与错误响应中不出现密码、令牌、会话标识原文，
 * 但保留可用于排查的关联标识（散列前缀，稳定且不可逆）。
 */
public final class Masking {

    private Masking() {}

    /**
     * 返回形如 {@code sha256:ab12cd34…} 的脱敏标识：
     * 只保留散列前 8 位，足以关联日志，无法还原原文。
     */
    public static String mask(String secret) {
        if (secret == null || secret.isEmpty()) {
            return "<empty>";
        }
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(secret.getBytes(StandardCharsets.UTF_8));
            return "sha256:" + HexFormat.of().formatHex(digest, 0, 4) + "…";
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
