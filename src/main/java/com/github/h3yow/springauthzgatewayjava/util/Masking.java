package com.github.h3yow.springauthzgatewayjava.util;

/**
 * 敏感 to sensitive fields: passwords, tokens, session ids must never appear
 * in logs or error responses in clear text, but a correlatable hint is kept.
 */
public final class Masking {

    private static final String HIDDEN = "***";
    private static final int PREFIX_LEN = 4;

    private Masking() {
    }

    /** 完全隐藏（用于口令等绝不可泄露的字段）。 */
    public static String hide(String secret) {
        return secret == null ? "null" : HIDDEN;
    }

    /** 保留前 4 个字符作为关联标识，其余隐藏（用于令牌/会话标识）。 */
    public static String prefix(String identifier) {
        if (identifier == null) {
            return "null";
        }
        if (identifier.length() <= PREFIX_LEN) {
            return HIDDEN;
        }
        return identifier.substring(0, PREFIX_LEN) + "...(" + identifier.length() + " chars)";
    }
}
