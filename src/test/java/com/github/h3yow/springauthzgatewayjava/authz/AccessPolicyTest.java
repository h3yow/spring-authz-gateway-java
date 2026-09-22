package com.github.h3yow.springauthzgatewayjava.authz;

import static org.junit.jupiter.api.Assertions.*;

import com.github.h3yow.springauthzgatewayjava.auth.Role;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class AccessPolicyTest {

    private static final Logger log = LoggerFactory.getLogger(AccessPolicyTest.class);
    private final AccessPolicy policy = new AccessPolicy();

    private AccessDecision decide(String path, Set<Role> roles, boolean authenticated) {
        AccessDecision d = policy.decide("GET", path, roles, authenticated);
        log.info("input: path={} roles={} authenticated={} -> permitted={} reason={}",
                path, roles, authenticated, d.permitted(), d.denyReason());
        return d;
    }

    @Test
    void publicResourcePermitsAnonymous() {
        assertTrue(decide("/api/public/info", Set.of(), false).permitted());
    }

    @Test
    void unauthenticatedIsDistinguishedFromForbidden() {
        AccessDecision unauth = decide("/api/user/profile", Set.of(), false);
        assertEquals(AccessDecision.DenyReason.UNAUTHENTICATED, unauth.denyReason());
        AccessDecision forbidden = decide("/api/admin/stats", Set.of(Role.USER), true);
        assertEquals(AccessDecision.DenyReason.FORBIDDEN_ROLE, forbidden.denyReason());
        assertNotEquals(unauth.denyReason(), forbidden.denyReason(), "未认证与未授权必须区分");
    }

    @Test
    void roleBasedAccess() {
        assertTrue(decide("/api/user/profile", Set.of(Role.USER), true).permitted());
        assertTrue(decide("/api/user/profile", Set.of(Role.ADMIN), true).permitted());
        assertTrue(decide("/api/admin/stats", Set.of(Role.ADMIN), true).permitted());
        assertFalse(decide("/api/admin/stats", Set.of(Role.USER), true).permitted(), "越权必须拒绝");
    }

    @Test
    void undeclaredResourceDefaultsToDeny() {
        AccessDecision d = decide("/api/undeclared", Set.of(Role.ADMIN), true);
        assertFalse(d.permitted(), "缺省策略必须是拒绝而非放行");
        assertEquals(AccessDecision.DenyReason.FORBIDDEN_RESOURCE, d.denyReason());
        assertFalse(decide("/actuator", Set.of(Role.ADMIN), true).permitted());
    }
}
