package com.github.h3yow.springauthzgatewayjava.web;

import com.github.h3yow.springauthzgatewayjava.authz.AccessDecision;
import com.github.h3yow.springauthzgatewayjava.authz.AccessDecisionService;
import com.github.h3yow.springauthzgatewayjava.authz.DenyReason;
import com.github.h3yow.springauthzgatewayjava.authz.RequiresPermission;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

/**
 * 依据 @RequiresPermission 进行授权判定：
 * 未认证抛 401，已认证但越权抛 403，原因稳定可区分。
 */
public class AuthzInterceptor implements HandlerInterceptor {

    private static final Logger log = LoggerFactory.getLogger(AuthzInterceptor.class);

    private final AccessDecisionService decisionService;

    public AuthzInterceptor(AccessDecisionService decisionService) {
        this.decisionService = decisionService;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        if (!(handler instanceof HandlerMethod handlerMethod)) {
            return true;
        }
        RequiresPermission required = handlerMethod.getMethodAnnotation(RequiresPermission.class);
        if (required == null) {
            return true;
        }
        AuthContext ctx = AuthContext.from(request);
        AccessDecision decision = decisionService.decide(
                ctx == null ? null : ctx.user(), required.role(), required.resource(), required.action());
        if (decision.granted()) {
            return true;
        }
        log.info("access denied path={} reason={} detail={}",
                request.getRequestURI(), decision.denyReason(), decision.explanation());
        if (decision.denyReason() == DenyReason.UNAUTHENTICATED) {
            throw new AuthException("UNAUTHENTICATED", "authentication required");
        }
        throw new AuthzException(decision.denyReason(), decision.explanation());
    }
}
