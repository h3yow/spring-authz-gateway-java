package com.github.h3yow.springauthzgatewayjava.auth;

import static org.junit.jupiter.api.Assertions.*;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** 活跃凭据自助管理：列举、撤销单个、撤销其他全部、并发撤销收敛。 */
class CredentialManagerTest {

    private static final Logger log = LoggerFactory.getLogger(CredentialManagerTest.class);

    private AuthProperties props() {
        AuthProperties p = new AuthProperties();
        p.setSessionTtl(Duration.ofMinutes(30));
        p.setSessionMaxLifetime(Duration.ofHours(12));
        p.setAccessTokenTtl(Duration.ofMinutes(10));
        p.setRefreshTokenTtl(Duration.ofHours(12));
        return p;
    }

    private record Fixture(SessionService sessions, TokenService tokens, CredentialManager manager) {}

    private Fixture fixture() {
        AuthProperties p = props();
        SessionService sessions = new SessionService(p);
        TokenService tokens = new TokenService(p);
        return new Fixture(sessions, tokens, new CredentialManager(sessions, tokens));
    }

    @Test
    void listContainsBothKindsWithMetadataButNoSecrets() {
        Fixture f = fixture();
        SessionRecord s = f.sessions().create("alice", Set.of(Role.USER), "browser-chrome");
        TokenService.TokenPair t = f.tokens().issue("alice", Set.of(Role.USER), "mobile-app");
        f.sessions().create("bob", Set.of(Role.USER), "other-user"); // 其他用户不得出现

        List<CredentialManager.CredentialView> views = f.manager().list("alice");
        log.info("input: alice has 1 session + 1 refresh credential -> {}", views);
        assertEquals(2, views.size());
        assertEquals(Set.of(CredentialManager.KIND_SESSION, CredentialManager.KIND_REFRESH_TOKEN),
                Set.of(views.get(0).kind(), views.get(1).kind()));
        for (CredentialManager.CredentialView v : views) {
            assertNotNull(v.credentialId());
            assertNotNull(v.issuedAt());
            assertNotNull(v.lastUsedAt());
            assertNotNull(v.expiresAt());
            // 绝不出现凭据本体
            assertNotEquals(s.sessionId(), v.credentialId());
            assertNotEquals(t.accessToken(), v.credentialId());
            assertNotEquals(t.refreshToken(), v.credentialId());
            assertFalse(v.credentialId().contains("."), "不得包含令牌串");
        }
        assertTrue(views.stream().anyMatch(v -> v.client().equals("browser-chrome")));
        assertTrue(views.stream().anyMatch(v -> v.client().equals("mobile-app")));
    }

    @Test
    void revokeOneAffectsOnlyTargetCredential() {
        Fixture f = fixture();
        SessionRecord s1 = f.sessions().create("alice", Set.of(Role.USER), "client-1");
        SessionRecord s2 = f.sessions().create("alice", Set.of(Role.USER), "client-2");
        String cid1 = f.manager().list("alice").stream()
                .filter(v -> v.client().equals("client-1")).findFirst().orElseThrow().credentialId();

        boolean hit = f.manager().revokeOne("alice", cid1);
        log.info("input: revokeOne(client-1 credential) -> hit={}", hit);
        assertTrue(hit);
        assertTrue(f.sessions().find(s1.sessionId()).isEmpty(), "目标凭据必须立即失效");
        assertTrue(f.sessions().find(s2.sessionId()).isPresent(), "其他客户端不得受影响");
        assertFalse(f.manager().revokeOne("alice", cid1), "重复撤销是幂等 no-op");
        // 不得撤销其他用户的凭据
        assertFalse(f.manager().revokeOne("bob", cid1));
    }

    @Test
    void revokeOneRefreshCredentialKillsDerivedAccessTokenImmediately() {
        Fixture f = fixture();
        TokenService.TokenPair client1 = f.tokens().issue("alice", Set.of(Role.USER), "client-1");
        TokenService.TokenPair client2 = f.tokens().issue("alice", Set.of(Role.USER), "client-2");
        String cid1 = f.tokens().credentialIdOf(client1.accessToken()).orElseThrow();

        boolean hit = f.manager().revokeOne("alice", cid1);
        log.info("input: revokeOne(refresh credential of client-1) -> hit={}", hit);
        assertTrue(hit);
        assertTrue(f.tokens().refresh(client1.refreshToken()).isEmpty(), "被撤销刷新令牌必须立即失效");
        assertTrue(f.tokens().verifyAccessToken(client1.accessToken()).isEmpty(),
                "其派生访问令牌必须立即失效");
        assertTrue(f.tokens().verifyAccessToken(client2.accessToken()).isPresent(),
                "其他客户端访问令牌不得受影响");
        assertTrue(f.tokens().refresh(client2.refreshToken()).isPresent(),
                "其他客户端刷新令牌不得受影响");
    }

    @Test
    void revokeAllExceptKeepsCurrentSession() {
        Fixture f = fixture();
        SessionRecord current = f.sessions().create("alice", Set.of(Role.USER), "current");
        SessionRecord other = f.sessions().create("alice", Set.of(Role.USER), "other");
        TokenService.TokenPair tokens = f.tokens().issue("alice", Set.of(Role.USER), "token-client");

        f.manager().revokeAllExcept("alice", CredentialManager.CurrentCredential.session(current.sessionId()));
        log.info("input: revokeAllExcept(current session)");
        assertTrue(f.sessions().find(current.sessionId()).isPresent(), "当前会话必须保留");
        assertTrue(f.sessions().find(other.sessionId()).isEmpty(), "其他会话必须撤销");
        assertTrue(f.tokens().verifyAccessToken(tokens.accessToken()).isEmpty(),
                "其他令牌凭据必须撤销");
        assertTrue(f.tokens().refresh(tokens.refreshToken()).isEmpty());
    }

    @Test
    void revokeAllExceptKeepsCurrentTokenCredential() {
        Fixture f = fixture();
        SessionRecord session = f.sessions().create("alice", Set.of(Role.USER), "browser");
        TokenService.TokenPair current = f.tokens().issue("alice", Set.of(Role.USER), "current-client");
        TokenService.TokenPair other = f.tokens().issue("alice", Set.of(Role.USER), "other-client");
        String currentCid = f.tokens().credentialIdOf(current.accessToken()).orElseThrow();

        f.manager().revokeAllExcept("alice", CredentialManager.CurrentCredential.token(currentCid));
        log.info("input: revokeAllExcept(current token credential)");
        assertTrue(f.tokens().verifyAccessToken(current.accessToken()).isPresent(),
                "当前访问令牌必须保留");
        assertTrue(f.tokens().refresh(current.refreshToken()).isPresent(),
                "当前刷新令牌必须保留");
        assertTrue(f.tokens().verifyAccessToken(other.accessToken()).isEmpty(),
                "其他访问令牌必须立即失效");
        assertTrue(f.tokens().refresh(other.refreshToken()).isEmpty(),
                "其他刷新令牌必须立即失效");
        assertTrue(f.sessions().find(session.sessionId()).isEmpty(), "其他会话必须撤销");
    }

    @Test
    void concurrentRevokeOneAndRevokeAllConverge() throws InterruptedException {
        Fixture f = fixture();
        int n = 16;
        SessionRecord[] sessions = new SessionRecord[n];
        String[] credentialIds = new String[n];
        for (int i = 0; i < n; i++) {
            sessions[i] = f.sessions().create("alice", Set.of(Role.USER), "client-" + i);
        }
        SessionRecord keep = f.sessions().create("alice", Set.of(Role.USER), "current");
        List<CredentialManager.CredentialView> listed = f.manager().list("alice");
        for (int i = 0; i < n; i++) {
            String client = "client-" + i;
            credentialIds[i] = listed.stream().filter(v -> v.client().equals(client))
                    .findFirst().orElseThrow().credentialId();
        }
        ExecutorService pool = Executors.newFixedThreadPool(24);
        CountDownLatch start = new CountDownLatch(1);
        // 线程组一：并发逐个撤销；线程组二：并发撤销全部（保留 current）；线程组三：重复撤销同一凭据
        for (int i = 0; i < n; i++) {
            final int idx = i;
            pool.submit(() -> {
                try {
                    start.await();
                    f.manager().revokeOne("alice", credentialIds[idx]);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        for (int i = 0; i < 4; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    f.manager().revokeAllExcept("alice",
                            CredentialManager.CurrentCredential.session(keep.sessionId()));
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        for (int i = 0; i < 4; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    f.manager().revokeOne("alice", credentialIds[0]); // 同一凭据并发重复撤销
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(15, TimeUnit.SECONDS));
        // 收敛断言：除保留的当前会话外，其余凭据全部失效；无复活、无遗漏
        for (int i = 0; i < n; i++) {
            assertTrue(f.sessions().find(sessions[i].sessionId()).isEmpty(),
                    "client-" + i + " 必须收敛到已撤销");
        }
        assertTrue(f.sessions().find(keep.sessionId()).isPresent(), "当前凭据必须保留");
        List<CredentialManager.CredentialView> remaining = f.manager().list("alice");
        log.info("input: concurrent revoke-one x{} + revoke-all x4 + duplicate x4 -> remaining={}",
                n, remaining.size());
        assertEquals(1, remaining.size(), "并发撤销后必须恰好只剩当前凭据");
        assertEquals("current", remaining.get(0).client());
    }
}
