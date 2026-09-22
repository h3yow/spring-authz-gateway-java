package com.github.h3yow.springauthzgatewayjava.authz;

/** 授权判定结果：拒绝原因可区分且稳定。 */
public record AccessDecision(boolean permitted, DenyReason denyReason) {

    public enum DenyReason {
        NONE,
        UNAUTHENTICATED,
        FORBIDDEN_ROLE,
        FORBIDDEN_RESOURCE
    }

    public static AccessDecision permit() {
        return new AccessDecision(true, DenyReason.NONE);
    }

    public static AccessDecision deny(DenyReason reason) {
        return new AccessDecision(false, reason);
    }
}
