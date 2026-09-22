package com.github.h3yow.springauthzgatewayjava.authz;

/**
 * 授权判定拒绝原因，未认证与未授权必须区分。
 */
public enum DenyReason {
    UNAUTHENTICATED,
    INSUFFICIENT_ROLE,
    MISSING_PERMISSION,
    DEFAULT_DENY
}
