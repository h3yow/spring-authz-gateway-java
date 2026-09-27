package com.github.h3yow.springauthzgatewayjava.auth;

import static org.junit.jupiter.api.Assertions.*;

import java.time.Duration;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 活跃凭据自助管理：视图只含元数据、单撤销互不影响、撤销其余全部只保留当前、跨用户隔离。
 */
class CredentialServiceTest {

    private static final Logger log = LoggerFactory.getLogger(CredentialServiceTest.class);

    private AuthProperties props;
    private SessionService sessions;
    private TokenService tokens;
    private CredentialService credentials;

    @BeforeEach
    void setUp() {
        props = new AuthProperties();
        props.setSessionIdleTtl(Duration.ofMinutes(30));
        props.setSessionMaxTtl(Duration.ofHours(12));
        props.setAccessTokenTtl(Duration.ofMinutes(10));
        props.setRefreshTokenTtl(Duration.ofHours(12));
        sessions = new SessionService(props);
        tokens = new TokenService(props);
        credentials = new CredentialService(sessions, tokens);
    }

    @Test
    void listActiveReturnsMetadataOnlyForAllKinds() {
        SessionRecord session = sessions.create("alice", Set.of(Role.USER), "client-a");
        TokenService.TokenPair pair = tokens.issue("alice", Set.of(Role.USER), "client-b");

        List<CredentialInfo> active = credentials.listActive("alice");
        log.info("input: one session + one token pair -> active count={}", active.size());
        assertEquals(2, active.size(), "会话与访问令牌都应出现在活跃列表");
        assertTrue(active.stream().anyMatch(i -> i.kind() == CredentialKind.SESSION));
        assertTrue(active.stream().anyMatch(i -> i.kind() == CredentialKind.ACCESS_TOKEN));

        CredentialInfo tokenInfo = active.stream()
                .filter(i -> i.kind() == CredentialKind.ACCESS_TOKEN).findFirst().orElseThrow();
        assertEquals("client-b", tokenInfo.clientKey());
        assertNotNull(tokenInfo.issuedAt());
        assertNotNull(tokenInfo.lastUsedAt());
        assertNotNull(tokenInfo.expiresAt());

        // 视图中绝不能出现凭据原文（Cookie 会话标识与令牌原文）
        String serialized = active.toString();
        assertFalse(serialized.contains(session.sessionId()), "列表不得暴露会话原文");
        assertFalse(serialized.contains(pair.accessToken()), "列表不得暴露访问令牌原文");
        assertFalse(serialized.contains(pair.refreshToken()), "列表不得暴露刷新令牌原文");
        log.info("decision: list contains only non-secret metadata");
    }

    @Test
    void revokeOneCredentialDoesNotAffectOthers() {
        SessionRecord sessionA = sessions.create("alice", Set.of(Role.USER), "client-a");
        SessionRecord sessionB = sessions.create("alice", Set.of(Role.USER), "client-b");
        TokenService.TokenPair tokenA = tokens.issue("alice", Set.of(Role.USER), "client-a");
        TokenService.TokenPair tokenB = tokens.issue("alice", Set.of(Role.USER), "client-b");

        // 撤销 client-a 的会话句柄：只影响该会话
        assertTrue(credentials.revokeCredential("alice", sessionA.credentialId()));
        assertTrue(sessions.find(sessionA.sessionId()).isEmpty(), "被撤销会话立即失效");
        assertTrue(sessions.find(sessionB.sessionId()).isPresent(), "其他客户端会话保持可用");
        assertTrue(tokens.verifyAccessToken(tokenA.accessToken()).isPresent(), "另一种凭据不受影响");
        assertTrue(tokens.verifyAccessToken(tokenB.accessToken()).isPresent());

        // 重复撤销幂等
        assertFalse(credentials.revokeCredential("alice", sessionA.credentialId()), "重复撤销返回 false");
        log.info("decision: single revoke isolated; repeat revoke idempotent");
    }

    @Test
    void revokeOthersKeepsOnlyCurrentCredential() {
        // 三个客户端：各自一个会话 + 一个访问令牌
        SessionRecord s1 = sessions.create("alice", Set.of(Role.USER), "client-a");
        SessionRecord s2 = sessions.create("alice", Set.of(Role.USER), "client-b");
        SessionRecord keep = sessions.create("alice", Set.of(Role.USER), "client-c");
        TokenService.TokenPair t1 = tokens.issue("alice", Set.of(Role.USER), "client-a");
        TokenService.TokenPair t2 = tokens.issue("alice", Set.of(Role.USER), "client-b");
        TokenService.TokenPair tKeep = tokens.issue("alice", Set.of(Role.USER), "client-c");

        int count = credentials.revokeOthers("alice", CredentialKind.SESSION, keep.credentialId());
        log.info("input: revoke-others keeping current session at client-c -> revokedCount={}", count);
        assertEquals(5, count, "另 2 个会话 + 3 个访问令牌（当前凭据是会话，令牌全撤）");

        assertTrue(sessions.find(s1.sessionId()).isEmpty());
        assertTrue(sessions.find(s2.sessionId()).isEmpty());
        assertTrue(sessions.find(keep.sessionId()).isPresent(), "当前会话必须保持可用");
        assertTrue(tokens.verifyAccessToken(t1.accessToken()).isEmpty());
        assertTrue(tokens.verifyAccessToken(t2.accessToken()).isEmpty());
        assertTrue(tokens.verifyAccessToken(tKeep.accessToken()).isEmpty(),
                "当前凭据是会话时，全部令牌都应撤销");

        // 重复调用幂等：当前会话仍在，其余已无可撤销
        assertEquals(0, credentials.revokeOthers("alice", CredentialKind.SESSION, keep.credentialId()));
        assertTrue(sessions.find(keep.sessionId()).isPresent());
    }

    @Test
    void revokeOthersKeepingTokenAlsoKeepsItsRefreshAbility() {
        SessionRecord s1 = sessions.create("alice", Set.of(Role.USER), "client-a");
        TokenService.TokenPair keepPair = tokens.issue("alice", Set.of(Role.USER), "client-b");
        String keepJti = tokens.jtiOf(keepPair.accessToken());

        credentials.revokeOthers("alice", CredentialKind.ACCESS_TOKEN, keepJti);
        assertTrue(sessions.find(s1.sessionId()).isEmpty());
        assertTrue(tokens.verifyAccessToken(keepPair.accessToken()).isPresent(), "当前令牌保持可用");
        assertTrue(tokens.refresh(keepPair.refreshToken()).isPresent(),
                "与当前令牌同对的刷新令牌应保留，当前客户端可继续刷新");
        log.info("decision: current token client stays fully usable after revoke-others");
    }

    @Test
    void userCannotTouchAnotherUsersCredential() {
        SessionRecord aliceSession = sessions.create("alice", Set.of(Role.USER), "client-a");
        TokenService.TokenPair aliceToken = tokens.issue("alice", Set.of(Role.USER), "client-a");
        String aliceJti = tokens.jtiOf(aliceToken.accessToken());

        assertFalse(credentials.revokeCredential("bob", aliceSession.credentialId()),
                "不得撤销他人会话");
        assertFalse(credentials.revokeCredential("bob", aliceJti), "不得撤销他人令牌");
        assertTrue(sessions.find(aliceSession.sessionId()).isPresent(), "归属校验失败时不得生效");
        assertTrue(tokens.verifyAccessToken(aliceToken.accessToken()).isPresent());

        // bob 的撤销其余全部也不得波及 alice
        credentials.revokeOthers("bob", null, null);
        assertTrue(sessions.find(aliceSession.sessionId()).isPresent());
        assertTrue(tokens.verifyAccessToken(aliceToken.accessToken()).isPresent());
        log.info("decision: cross-user revocation attempts are isolated");
    }
}
