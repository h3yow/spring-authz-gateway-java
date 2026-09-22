package com.github.h3yow.springauthzgatewayjava.web;

/**
 * 统一错误响应体：含可区分的错误码与关联标识，不含敏感原文。
 */
public record ApiError(String code, String message, String correlationId) {
}
