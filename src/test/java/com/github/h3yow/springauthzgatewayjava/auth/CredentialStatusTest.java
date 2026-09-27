package com.github.h3yow.springauthzgatewayjava.auth;

import static org.junit.jupiter.api.Assertions.*;

import java.time.Duration;
import java.time.Instant;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** "没有凭据 / 已撤销 / 已过期"的可区分判定（服务层）。 */
class CredentialStatusTest {

    private static final Logger log = LoggerFactory.getLogger(CredentialStatusTest.class);
    private static final Instant T0 = Instant.parse("2026-09-27T00:00:00Z");

    private AuthProperties props() {
        AuthProperties p = new AuthProperties();
        p.setSessionTtl(Duration.ofMinutes(30));
        p.setSessionMaxLifetime(Duration.ofHours(12));
        p.setAccessTokenTtl(Duration.ofMinutes(10));
        p.setRefreshTokenTtl(Duration.ofHours(12));
        return p;
    }

    @Test
    void sessionEvaluationDistinguishesValidExpiredUnknown() {
        LoginGuardTest.MutableClock clock = new LoginGuardTest.MutableClock(T0);
        SessionService sessions = new SessionService(props(), clock);
        SessionRecord valid = sessions.create("alice", Set.of(Role.USER));
        SessionRecord expiring = sessions.create("alice", Set.of(Role.USER));
        SessionRecord revoked = sessions.create("alice", Set.of(Role.USER));

        sessions.revoke(revoked.sessionId());
        clock.advance(Duration.ofMinutes(31)); // expiring 过期；valid 因 ttl 相同也过期，重建一个
        SessionRecord fresh = sessions.create("alice", Set.of(Role.USER));

        assertEquals(SessionService.SessionStatus.VALID, sessions.evaluate(fresh.sessionId()).status());
        assertEquals(SessionService.SessionStatus.EXPIRED, sessions.evaluate(expiring.sessionId()).status());
        assertEquals(SessionService.SessionStatus.UNKNOWN, sessions.evaluate(revoked.sessionId()).status());
        assertEquals(SessionService.SessionStatus.UNKNOWN, sessions.evaluate("never-existed").status());
        assertEquals(SessionService.SessionStatus.UNKNOWN, sessions.evaluate(null).status());
        log.info("decision: valid/expired/revoked+unknown 三态可区分（撤销与未知对外不可区分）");
    }

    @Test
    void tokenEvaluationDistinguishesValidExpiredInvalid() {
        LoginGuardTest.MutableClock clock = new LoginGuardTest.MutableClock(T0);
        TokenService tokens = new TokenService(props(), clock, new byte[32]);
        TokenService.TokenPair pair = tokens.issue("alice", Set.of(Role.USER));
        TokenService.TokenPair doomed = tokens.issue("alice", Set.of(Role.USER));

        assertEquals(TokenService.TokenStatus.VALID, tokens.evaluateAccessToken(pair.accessToken()));
        // 撤销单个凭据 -> INVALID（立即）
        String doomedCid = tokens.credentialIdOf(doomed.accessToken()).orElseThrow();
        tokens.revokeByCredentialId("alice", doomedCid);
        assertEquals(TokenService.TokenStatus.INVALID, tokens.evaluateAccessToken(doomed.accessToken()));
        assertEquals(TokenService.TokenStatus.VALID, tokens.evaluateAccessToken(pair.accessToken()),
                "撤销一个凭据不得误伤同用户其他凭据");
        // 过期 -> EXPIRED
        clock.advance(Duration.ofMinutes(11));
        assertEquals(TokenService.TokenStatus.EXPIRED, tokens.evaluateAccessToken(pair.accessToken()));
        // 伪造/畸形 -> INVALID
        assertEquals(TokenService.TokenStatus.INVALID, tokens.evaluateAccessToken("garbage"));
        assertEquals(TokenService.TokenStatus.INVALID, tokens.evaluateAccessToken(null));
        log.info("decision: VALID/EXPIRED/INVALID 三态可区分");
    }
}
