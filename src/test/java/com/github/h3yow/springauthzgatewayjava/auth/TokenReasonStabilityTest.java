package com.github.h3yow.springauthzgatewayjava.auth;

import static org.junit.jupiter.api.Assertions.*;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 同一令牌凭据拒绝原因稳定，覆盖撤销/过期/已用三类终态：
 * 已撤销令牌越过自然过期点后仍稳定 INVALID（不漂移成 EXPIRED）；
 * 未撤销的过期令牌稳定 EXPIRED；刷新令牌消费（旋转）后稳定 INVALID；
 * 过期刷新令牌稳定 EXPIRED。
 */
class TokenReasonStabilityTest {

    private static final Logger log = LoggerFactory.getLogger(TokenReasonStabilityTest.class);
    private static final Instant T0 = Instant.parse("2026-09-28T00:00:00Z");

    private AuthProperties props() {
        AuthProperties p = new AuthProperties();
        p.setAccessTokenTtl(Duration.ofMinutes(10));
        p.setRefreshTokenTtl(Duration.ofMinutes(60));
        p.setRevocationRetention(Duration.ofHours(2));
        return p;
    }

    @Test
    void revokedAccessTokenStaysInvalidAfterNaturalExpiry() {
        LoginGuardTest.MutableClock clock = new LoginGuardTest.MutableClock(T0);
        TokenService tokens = new TokenService(props(), clock, new byte[32]);
        TokenService.TokenPair doomed = tokens.issue("alice", Set.of(Role.USER));
        String cid = tokens.credentialIdOf(doomed.accessToken()).orElseThrow();
        tokens.revokeByCredentialId("alice", cid);

        assertEquals(TokenService.TokenStatus.INVALID, tokens.evaluateAccessToken(doomed.accessToken()));
        clock.advance(Duration.ofMinutes(30)); // 远超访问令牌自然过期(10m)
        for (int i = 0; i < 3; i++) {
            TokenService.TokenStatus status = tokens.evaluateAccessToken(doomed.accessToken());
            log.info("input: revoked access token past natural expiry, eval #{} -> {}", i + 1, status);
            assertEquals(TokenService.TokenStatus.INVALID, status,
                    "已撤销令牌在自然过期后不得漂移为 EXPIRED（撤销优先 + 墓碑保留）");
        }
    }

    @Test
    void expiredAccessTokenReasonIsStable() {
        LoginGuardTest.MutableClock clock = new LoginGuardTest.MutableClock(T0);
        TokenService tokens = new TokenService(props(), clock, new byte[32]);
        TokenService.TokenPair pair = tokens.issue("alice", Set.of(Role.USER));
        clock.advance(Duration.ofMinutes(11));
        for (int i = 0; i < 3; i++) {
            assertEquals(TokenService.TokenStatus.EXPIRED,
                    tokens.evaluateAccessToken(pair.accessToken()),
                    "同一过期令牌重复判定必须稳定为 EXPIRED");
        }
        log.info("decision: expired access token stays EXPIRED across repeated requests");
    }

    @Test
    void consumedRefreshTokenStaysInvalidAndDoesNotDriftToExpired() {
        LoginGuardTest.MutableClock clock = new LoginGuardTest.MutableClock(T0);
        TokenService tokens = new TokenService(props(), clock, new byte[32]);
        TokenService.TokenPair first = tokens.issue("alice", Set.of(Role.USER));
        Optional<TokenService.TokenPair> rotated = tokens.refresh(first.refreshToken());
        assertTrue(rotated.isPresent());
        assertEquals(TokenService.RefreshStatus.INVALID, tokens.evaluateRefreshToken(first.refreshToken()),
                "旋转消费后应为 INVALID");
        clock.advance(Duration.ofMinutes(61)); // 越过刷新令牌自然过期
        for (int i = 0; i < 3; i++) {
            assertEquals(TokenService.RefreshStatus.INVALID,
                    tokens.evaluateRefreshToken(first.refreshToken()),
                    "已用刷新令牌越过自然过期点后仍必须稳定 INVALID，不得漂移为 EXPIRED");
            assertTrue(tokens.refresh(first.refreshToken()).isEmpty());
        }
        log.info("decision: consumed refresh token stays INVALID past natural expiry");
    }

    @Test
    void expiredRefreshTokenStaysExpired() {
        LoginGuardTest.MutableClock clock = new LoginGuardTest.MutableClock(T0);
        TokenService tokens = new TokenService(props(), clock, new byte[32]);
        TokenService.TokenPair pair = tokens.issue("alice", Set.of(Role.USER));
        clock.advance(Duration.ofMinutes(61));
        for (int i = 0; i < 3; i++) {
            assertEquals(TokenService.RefreshStatus.EXPIRED,
                    tokens.evaluateRefreshToken(pair.refreshToken()),
                    "未撤销的过期刷新令牌必须稳定为 EXPIRED");
        }
        log.info("decision: untouched expired refresh token stays EXPIRED");
    }

    @Test
    void epochRevokedRefreshTokenStaysInvalidPastExpiry() {
        LoginGuardTest.MutableClock clock = new LoginGuardTest.MutableClock(T0);
        TokenService tokens = new TokenService(props(), clock, new byte[32]);
        TokenService.TokenPair pair = tokens.issue("alice", Set.of(Role.USER));
        tokens.revokeAllForUser("alice"); // 纪元撤销
        assertEquals(TokenService.RefreshStatus.INVALID, tokens.evaluateRefreshToken(pair.refreshToken()));
        clock.advance(Duration.ofMinutes(61));
        assertEquals(TokenService.RefreshStatus.INVALID,
                tokens.evaluateRefreshToken(pair.refreshToken()),
                "纪元撤销的刷新令牌越过过期点后仍稳定 INVALID");
        log.info("decision: epoch-revoked refresh token stays INVALID past expiry");
    }
}
