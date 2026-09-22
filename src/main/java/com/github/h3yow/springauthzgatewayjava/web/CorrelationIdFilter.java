package com.github.h3yow.springauthzgatewayjava.web;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.UUID;
import org.slf4j.MDC;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * 为每个请求分配关联标识：写入请求属性、响应头与 MDC，
 * 供日志与错误响应串联排查，同时避免在日志中输出敏感原文。
 */
public class CorrelationIdFilter extends OncePerRequestFilter {

    public static final String REQUEST_ATTRIBUTE = CorrelationIdFilter.class.getName() + ".ID";
    public static final String HEADER = "X-Correlation-Id";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String id = UUID.randomUUID().toString().substring(0, 8);
        request.setAttribute(REQUEST_ATTRIBUTE, id);
        response.setHeader(HEADER, id);
        MDC.put("cid", id);
        try {
            chain.doFilter(request, response);
        } finally {
            MDC.remove("cid");
        }
    }

    public static String currentId(HttpServletRequest request) {
        Object id = request.getAttribute(REQUEST_ATTRIBUTE);
        return id == null ? "n/a" : id.toString();
    }
}
