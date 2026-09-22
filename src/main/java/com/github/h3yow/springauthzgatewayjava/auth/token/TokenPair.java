package com.github.h3yow.springauthzgatewayjava.auth.token;

/**
 * 访问令牌 + 刷新令牌。
 */
public record TokenPair(String accessToken, String refreshToken, long accessTokenExpiresInSeconds) {
}
