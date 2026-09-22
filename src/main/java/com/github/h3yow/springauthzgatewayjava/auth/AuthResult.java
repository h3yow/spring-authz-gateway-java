package com.github.h3yow.springauthzgatewayjava.auth;

/** 认证结果：成功携带会话与令牌，失败携带内部原因。 */
public record AuthResult(
        boolean success,
        AuthFailureReason failureReason,
        SessionRecord session,
        String accessToken,
        String refreshToken) {

    public static AuthResult ok(SessionRecord session, String accessToken, String refreshToken) {
        return new AuthResult(true, null, session, accessToken, refreshToken);
    }

    public static AuthResult fail(AuthFailureReason reason) {
        return new AuthResult(false, reason, null, null, null);
    }
}
