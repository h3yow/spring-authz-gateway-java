package com.github.h3yow.springauthzgatewayjava.auth;

/** 认证失败的内部可区分原因（对外统一为无效凭据，不泄露账号是否存在）。 */
public enum AuthFailureReason {
    ACCOUNT_NOT_FOUND,
    ACCOUNT_DISABLED,
    CREDENTIALS_EXPIRED,
    BAD_PASSWORD,
    ACCOUNT_LOCKED,
    RATE_LIMITED
}
