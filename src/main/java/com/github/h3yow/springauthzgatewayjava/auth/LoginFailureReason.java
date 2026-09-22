package com.github.h3yow.springauthzgatewayjava.auth;

/**
 * 登录失败原因。注意：INVALID_CREDENTIALS 同时覆盖“账号不存在”和“口令错误”，
 * 不得向外部泄露账号是否存在。
 */
public enum LoginFailureReason {
    INVALID_CREDENTIALS,
    ACCOUNT_LOCKED,
    ACCOUNT_DISABLED,
    CREDENTIALS_EXPIRED
}
