package com.github.h3yow.springauthzgatewayjava.web;

/**
 * 统一错误响应：含可归类错误码与关联标识，不含敏感信息。
 * {@code reason} 为可空的细分原因（如 401 的 NO_CREDENTIALS / CREDENTIAL_EXPIRED /
 * CREDENTIAL_REVOKED），用于让客户端稳定区分判定结果。
 */
public record ApiError(String code, String message, String correlationId, String reason) {

    public ApiError(String code, String message, String correlationId) {
        this(code, message, correlationId, null);
    }
}
