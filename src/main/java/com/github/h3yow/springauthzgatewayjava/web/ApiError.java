package com.github.h3yow.springauthzgatewayjava.web;

/** 统一错误响应：含可归类错误码与关联标识，不含敏感信息。 */
public record ApiError(String code, String message, String correlationId) {}
