package com.github.h3yow.springauthzgatewayjava.web;

import com.github.h3yow.springauthzgatewayjava.auth.LoginFailureReason;

/**
 * 认证失败异常（HTTP 401）。
 */
public class AuthException extends RuntimeException {

    private final String code;

    public AuthException(String code, String message) {
        super(message);
        this.code = code;
    }

    public static AuthException loginFailed(LoginFailureReason reason) {
        return new AuthException(reason.name(), "login failed: " + reason.name());
    }

    public String getCode() {
        return code;
    }
}
