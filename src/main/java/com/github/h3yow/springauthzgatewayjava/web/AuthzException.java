package com.github.h3yow.springauthzgatewayjava.web;

import com.github.h3yow.springauthzgatewayjava.authz.DenyReason;

/**
 * 授权失败异常（HTTP 403），携带稳定的拒绝原因。
 */
public class AuthzException extends RuntimeException {

    private final DenyReason reason;

    public AuthzException(DenyReason reason, String message) {
        super(message);
        this.reason = reason;
    }

    public DenyReason getReason() {
        return reason;
    }
}
