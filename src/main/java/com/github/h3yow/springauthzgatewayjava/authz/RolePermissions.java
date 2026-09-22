package com.github.h3yow.springauthzgatewayjava.authz;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Component;

/**
 * 角色 → 权限（resource:action）映射。支持通配：resource:* 与 *:*。
 * 缺省仅含最小权限，未列出的角色没有任何权限（缺省拒绝）。
 */
@Component
public class RolePermissions {

    private final Map<String, Set<String>> grants = new ConcurrentHashMap<>(Map.of(
            "ADMIN", Set.of("*:*"),
            "USER", Set.of("profile:read", "documents:read")
    ));

    public Set<String> permissionsOf(String role) {
        return grants.getOrDefault(role, Set.of());
    }

    /** 测试或管理用途：覆盖某角色的权限集。 */
    public void setPermissions(String role, Set<String> permissions) {
        grants.put(role, Set.copyOf(permissions));
    }

    public boolean grants(String role, String resource, String action) {
        Set<String> perms = permissionsOf(role);
        return perms.contains("*:*")
                || perms.contains(resource + ":*")
                || perms.contains(resource + ":" + action);
    }
}
