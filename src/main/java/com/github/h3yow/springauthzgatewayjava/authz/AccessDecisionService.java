package com.github.h3yow.springauthzgatewayjava.authz;

import com.github.h3yow.springauthzgatewayjava.auth.AuthUser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * 基于角色与资源的权限判定：
 * - 未认证 → UNAUTHENTICATED；
 * - 指定了必需角色而账号不具备 → INSUFFICIENT_ROLE；
 * - 角色未覆盖 resource:action 权限 → MISSING_PERMISSION；
 * - 缺省策略为拒绝，绝不放行。
 */
@Service
public class AccessDecisionService {

    private static final Logger log = LoggerFactory.getLogger(AccessDecisionService.class);

    private final RolePermissions rolePermissions;

    public AccessDecisionService(RolePermissions rolePermissions) {
        this.rolePermissions = rolePermissions;
    }

    public AccessDecision decide(AuthUser user, String requiredRole, String resource, String action) {
        if (user == null) {
            return logAndReturn(AccessDecision.deny(DenyReason.UNAUTHENTICATED,
                    "no authenticated principal for " + resource + ":" + action));
        }
        if (!user.enabled()) {
            return logAndReturn(AccessDecision.deny(DenyReason.DEFAULT_DENY,
                    "disabled account must not hold any permission"));
        }
        if (requiredRole != null && !requiredRole.isBlank() && !user.roles().contains(requiredRole)) {
            return logAndReturn(AccessDecision.deny(DenyReason.INSUFFICIENT_ROLE,
                    "user=" + user.username() + " lacks role=" + requiredRole));
        }
        boolean granted = user.roles().stream()
                .anyMatch(role -> rolePermissions.grants(role, resource, action));
        if (!granted) {
            return logAndReturn(AccessDecision.deny(DenyReason.MISSING_PERMISSION,
                    "user=" + user.username() + " roles=" + user.roles()
                            + " do not grant " + resource + ":" + action));
        }
        return logAndReturn(AccessDecision.grant(
                "user=" + user.username() + " granted " + resource + ":" + action));
    }

    private AccessDecision logAndReturn(AccessDecision decision) {
        log.info("access decision granted={} reason={} detail={}",
                decision.granted(), decision.denyReason(), decision.explanation());
        return decision;
    }
}
