package com.github.h3yow.springauthzgatewayjava.web;

import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * 统一异常映射：认证失败 401、授权失败 403、CSRF 失败 403，
 * 响应体只含错误码与关联标识，绝不含口令、令牌或会话标识原文。
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(AuthException.class)
    public ResponseEntity<ApiError> handleAuth(AuthException ex, HttpServletRequest request) {
        // 登录类失败（如 INVALID_CREDENTIALS）属于 401；CSRF 属于 403
        HttpStatus status = ex.getCode().startsWith("CSRF") ? HttpStatus.FORBIDDEN : HttpStatus.UNAUTHORIZED;
        return build(status, ex.getCode(), ex.getMessage(), request);
    }

    @ExceptionHandler(AuthzException.class)
    public ResponseEntity<ApiError> handleAuthz(AuthzException ex, HttpServletRequest request) {
        return build(HttpStatus.FORBIDDEN, ex.getReason().name(), ex.getMessage(), request);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiError> handleOther(Exception ex, HttpServletRequest request) {
        log.error("unhandled error cid={} type={}", CorrelationIdFilter.currentId(request),
                ex.getClass().getSimpleName(), ex);
        return build(HttpStatus.INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", "internal error", request);
    }

    private ResponseEntity<ApiError> build(HttpStatus status, String code, String message, HttpServletRequest request) {
        String cid = CorrelationIdFilter.currentId(request);
        log.info("error response cid={} status={} code={}", cid, status.value(), code);
        return ResponseEntity.status(status).body(new ApiError(code, message, cid));
    }
}
