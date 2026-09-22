package com.github.h3yow.springauthzgatewayjava.authz;

import com.github.h3yow.springauthzgatewayjava.auth.Role;
import java.util.List;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * 基于角色与资源的权限判定。
 *
 * <p>规则按声明顺序匹配；未匹配任何规则时缺省拒绝（deny-by-default）。
 * 未认证（UNAUTHENTICATED）与已认证但越权（FORBIDDEN_*）严格区分。
 */
@Component
public class AccessPolicy {

    private static final Logger log = LoggerFactory.getLogger(AccessPolicy.class);

    /** 资源规则：路径前缀 -> 允许的角色集合；空集合表示公开资源。 */
    private record Rule(String pathPrefix, Set<Role> anyOfRoles) {}

    private static final List<Rule> RULES = List.of(
            new Rule("/api/public", Set.of()),
            new Rule("/api/auth", Set.of()),
            new Rule("/api/admin", Set.of(Role.ADMIN)),
            new Rule("/api/user", Set.of(Role.USER, Role.ADMIN))
    );

    /**
     * @param authenticated 是否已通过任一凭据认证
     * @param roles         认证主体的角色（未认证时为空集）
     */
    public AccessDecision decide(String method, String path, Set<Role> roles, boolean authenticated) {
        for (Rule rule : RULES) {
            if (!path.startsWith(rule.pathPrefix())) {
                continue;
            }
            if (rule.anyOfRoles().isEmpty()) {
                return AccessDecision.permit(); // 公开资源
            }
            if (!authenticated) {
                return logAndReturn(path, AccessDecision.DenyReason.UNAUTHENTICATED, roles);
            }
            boolean roleOk = roles.stream().anyMatch(rule.anyOfRoles()::contains);
            return roleOk ? AccessDecision.permit()
                    : logAndReturn(path, AccessDecision.DenyReason.FORBIDDEN_ROLE, roles);
        }
        // 缺省拒绝：未声明的资源一律不放行
        return logAndReturn(path, AccessDecision.DenyReason.FORBIDDEN_RESOURCE, roles);
    }

    private AccessDecision logAndReturn(String path, AccessDecision.DenyReason reason, Set<Role> roles) {
        log.info("access denied path={} reason={} roles={}", path, reason, roles);
        return AccessDecision.deny(reason);
    }
}
