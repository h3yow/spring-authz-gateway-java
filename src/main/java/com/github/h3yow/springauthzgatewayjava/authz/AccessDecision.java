package com.github.h3yow.springauthzgatewayjava.authz;

/**
 * 授权判定结果：放行或带稳定原因的拒绝。
 */
public record AccessDecision(boolean granted, DenyReason denyReason, String explanation) {

    public static AccessDecision grant(String explanation) {
        return new AccessDecision(true, null, explanation);
    }

    public static AccessDecision deny(DenyReason reason, String explanation) {
        return new AccessDecision(false, reason, explanation);
    }
}
