package com.github.h3yow.springauthzgatewayjava.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.h3yow.springauthzgatewayjava.auth.AuthUser;
import com.github.h3yow.springauthzgatewayjava.authz.AccessDecision;
import com.github.h3yow.springauthzgatewayjava.authz.AccessDecisionService;
import com.github.h3yow.springauthzgatewayjava.authz.DenyReason;
import com.github.h3yow.springauthzgatewayjava.authz.RolePermissions;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class AccessDecisionServiceTest {

    private static final Logger log = LoggerFactory.getLogger(AccessDecisionServiceTest.class);

    private AccessDecisionService decisionService;

    private static AuthUser user(String name, String... roles) {
        return new AuthUser(name, "hash", Set.of(roles), true, false);
    }

    @BeforeEach
    void setUp() {
        decisionService = new AccessDecisionService(new RolePermissions());
    }

    private void logDecision(String scenario, AccessDecision d) {
        log.info("scenario={} granted={} reason={} detail={}",
                scenario, d.granted(), d.denyReason(), d.explanation());
    }

    @Test
    void unauthenticatedIsDistinguishedFromUnauthorized() {
        AccessDecision anon = decisionService.decide(null, "", "profile", "read");
        AccessDecision forbidden = decisionService.decide(user("bob", "USER"), "", "admin", "read");
        logDecision("anonymous", anon);
        logDecision("authenticated-but-forbidden", forbidden);
        assertEquals(DenyReason.UNAUTHENTICATED, anon.denyReason());
        assertEquals(DenyReason.MISSING_PERMISSION, forbidden.denyReason());
    }

    @Test
    void defaultPolicyIsDeny() {
        AccessDecision d = decisionService.decide(user("bob", "USER"), "", "unknown-resource", "unknown-action");
        logDecision("no matching grant", d);
        assertFalse(d.granted(), "缺省策略必须为拒绝");
        assertEquals(DenyReason.MISSING_PERMISSION, d.denyReason());
    }

    @Test
    void userRoleGrantsProfileRead() {
        AccessDecision d = decisionService.decide(user("bob", "USER"), "", "profile", "read");
        logDecision("USER reads profile", d);
        assertTrue(d.granted());
    }

    @Test
    void userRoleCannotWriteDocuments() {
        AccessDecision d = decisionService.decide(user("bob", "USER"), "", "documents", "write");
        logDecision("USER writes documents", d);
        assertFalse(d.granted());
        assertEquals(DenyReason.MISSING_PERMISSION, d.denyReason());
    }

    @Test
    void adminWildcardGrantsEverything() {
        AccessDecision d = decisionService.decide(user("alice", "ADMIN"), "", "admin", "read");
        logDecision("ADMIN reads admin", d);
        assertTrue(d.granted());
    }

    @Test
    void requiredRoleEnforcedSeparately() {
        AccessDecision d = decisionService.decide(user("bob", "USER"), "ADMIN", "admin", "read");
        logDecision("USER accessing ADMIN-required endpoint", d);
        assertFalse(d.granted());
        assertEquals(DenyReason.INSUFFICIENT_ROLE, d.denyReason());
    }

    @Test
    void disabledAccountGetsNoPermission() {
        AuthUser disabled = new AuthUser("carol", "hash", Set.of("ADMIN"), false, false);
        AccessDecision d = decisionService.decide(disabled, "", "admin", "read");
        logDecision("disabled admin", d);
        assertFalse(d.granted(), "停用账号不得持有任何权限");
        assertEquals(DenyReason.DEFAULT_DENY, d.denyReason());
    }

    @Test
    void denyReasonsAreStableAcrossRepeatedCalls() {
        AccessDecision first = decisionService.decide(user("bob", "USER"), "", "documents", "write");
        AccessDecision second = decisionService.decide(user("bob", "USER"), "", "documents", "write");
        logDecision("repeat #1", first);
        logDecision("repeat #2", second);
        assertEquals(first.denyReason(), second.denyReason(), "相同输入的拒绝原因必须稳定");
    }
}
