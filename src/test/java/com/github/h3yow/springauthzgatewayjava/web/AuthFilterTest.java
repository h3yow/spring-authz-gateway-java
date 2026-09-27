package com.github.h3yow.springauthzgatewayjava.web;

import static org.junit.jupiter.api.Assertions.*;

import com.github.h3yow.springauthzgatewayjava.auth.AuthProperties;
import com.github.h3yow.springauthzgatewayjava.auth.CredentialKind;
import com.github.h3yow.springauthzgatewayjava.auth.Role;
import com.github.h3yow.springauthzgatewayjava.auth.SessionRecord;
import com.github.h3yow.springauthzgatewayjava.auth.SessionService;
import com.github.h3yow.springauthzgatewayjava.auth.TokenService;
import com.github.h3yow.springauthzgatewayjava.authz.AccessPolicy;
import jakarta.servlet.http.Cookie;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

/**
 * 过滤器判定结果单测：未携带/已撤销/已过期/不被认可 四种状态稳定可区分；
 * 一种失效凭据不拖累另一种有效凭据；会话滑动续期结果通过响应头明确告知。
 */
class AuthFilterTest {

    private static final Logger log = LoggerFactory.getLogger(AuthFilterTest.class);

    /** 可推进的测试时钟。 */
    static final class MutableClock extends Clock {
        private Instant now;
        MutableClock(Instant start) { this.now = start; }
        void advance(Duration d) { now = now.plus(d); }
        @Override public Instant instant() { return now; }
        @Override public ZoneId getZone() { return ZoneId.of("UTC"); }
        @Override public Clock withZone(ZoneId zone) { return this; }
    }

    private MutableClock clock;
    private SessionService sessions;
    private TokenService tokens;
    private AuthFilter filter;

    @BeforeEach
    void setUp() {
        AuthProperties props = new AuthProperties();
        props.setSessionIdleTtl(Duration.ofMinutes(30));
        props.setSessionMaxTtl(Duration.ofHours(12));
        props.setAccessTokenTtl(Duration.ofMinutes(10));
        props.setRefreshTokenTtl(Duration.ofHours(12));
        clock = new MutableClock(Instant.parse("2026-09-27T00:00:00Z"));
        sessions = new SessionService(props, clock);
        tokens = new TokenService(props, clock, new byte[32]);
        filter = new AuthFilter(sessions, tokens, new AccessPolicy());
    }

    private MockHttpServletRequest protectedRequest() {
        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/api/user/profile");
        req.setRequestURI("/api/user/profile");
        return req;
    }

    @Test
    void missingCredentialYieldsCredentialMissing() throws Exception {
        MockHttpServletResponse res = new MockHttpServletResponse();
        filter.doFilter(protectedRequest(), res, new MockFilterChain());
        log.info("input: no credentials -> {} {}", res.getStatus(), res.getContentAsString());
        assertEquals(401, res.getStatus());
        assertTrue(res.getContentAsString().contains("CREDENTIAL_MISSING"));
    }

    @Test
    void revokedCredentialYieldsCredentialRevoked() throws Exception {
        SessionRecord s = sessions.create("alice", Set.of(Role.USER), "client-a");
        sessions.revoke(s.sessionId());
        MockHttpServletRequest req = protectedRequest();
        req.setCookies(new Cookie(AuthFilter.SESSION_COOKIE, s.sessionId()));
        MockHttpServletResponse res = new MockHttpServletResponse();
        filter.doFilter(req, res, new MockFilterChain());
        log.info("input: revoked session -> {} {}", res.getStatus(), res.getContentAsString());
        assertEquals(401, res.getStatus());
        assertTrue(res.getContentAsString().contains("CREDENTIAL_REVOKED"));
        assertFalse(res.getContentAsString().contains(s.sessionId()), "响应不得包含凭据原文");
    }

    @Test
    void expiredCredentialYieldsCredentialExpired() throws Exception {
        SessionRecord s = sessions.create("alice", Set.of(Role.USER), "client-a");
        clock.advance(Duration.ofMinutes(31)); // 超过空闲阈值但未撤销
        MockHttpServletRequest req = protectedRequest();
        req.setCookies(new Cookie(AuthFilter.SESSION_COOKIE, s.sessionId()));
        MockHttpServletResponse res = new MockHttpServletResponse();
        filter.doFilter(req, res, new MockFilterChain());
        log.info("input: expired session -> {} {}", res.getStatus(), res.getContentAsString());
        assertEquals(401, res.getStatus());
        assertTrue(res.getContentAsString().contains("CREDENTIAL_EXPIRED"));
    }

    @Test
    void forgedCredentialYieldsCredentialInvalid() throws Exception {
        MockHttpServletRequest req = protectedRequest();
        req.addHeader("Authorization", "Bearer forged.token.value");
        MockHttpServletResponse res = new MockHttpServletResponse();
        filter.doFilter(req, res, new MockFilterChain());
        log.info("input: forged bearer -> {} {}", res.getStatus(), res.getContentAsString());
        assertEquals(401, res.getStatus());
        assertTrue(res.getContentAsString().contains("CREDENTIAL_INVALID"));
    }

    @Test
    void validBearerIsNotDraggedDownByStaleSessionCookie() throws Exception {
        SessionRecord stale = sessions.create("alice", Set.of(Role.USER), "client-a");
        sessions.revoke(stale.sessionId());
        TokenService.TokenPair pair = tokens.issue("alice", Set.of(Role.USER), "client-b");

        MockHttpServletRequest req = protectedRequest();
        req.setCookies(new Cookie(AuthFilter.SESSION_COOKIE, stale.sessionId()));
        req.addHeader("Authorization", "Bearer " + pair.accessToken());
        MockHttpServletResponse res = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        filter.doFilter(req, res, chain);

        AuthContext ctx = (AuthContext) req.getAttribute(AuthContext.REQUEST_ATTRIBUTE);
        log.info("input: revoked session cookie + valid bearer -> chainReached={} kind={}",
                chain.getRequest() != null, ctx != null ? ctx.kind() : null);
        assertNotNull(chain.getRequest(), "有效 Bearer 必须放行，不受失效会话 Cookie 拖累");
        assertNotNull(ctx);
        assertEquals(CredentialKind.ACCESS_TOKEN, ctx.kind());
        assertEquals(200, res.getStatus());
    }

    @Test
    void validSessionIsNotDraggedDownByForgedBearer() throws Exception {
        SessionRecord s = sessions.create("alice", Set.of(Role.USER), "client-a");
        MockHttpServletRequest req = protectedRequest();
        req.setCookies(new Cookie(AuthFilter.SESSION_COOKIE, s.sessionId()));
        req.addHeader("Authorization", "Bearer forged.token.value");
        MockHttpServletResponse res = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        filter.doFilter(req, res, chain);
        assertNotNull(chain.getRequest(), "有效会话必须放行，不受伪造 Bearer 拖累");
        AuthContext ctx = (AuthContext) req.getAttribute(AuthContext.REQUEST_ATTRIBUTE);
        assertEquals(CredentialKind.SESSION, ctx.kind());
        log.info("decision: valid session wins over forged bearer");
    }

    @Test
    void sessionAuthEmitsSlidingRenewalHeaders() throws Exception {
        SessionRecord s = sessions.create("alice", Set.of(Role.USER), "client-a");
        MockHttpServletRequest req = protectedRequest();
        req.setCookies(new Cookie(AuthFilter.SESSION_COOKIE, s.sessionId()));
        MockHttpServletResponse res = new MockHttpServletResponse();
        filter.doFilter(req, res, new MockFilterChain());

        assertNotNull(res.getHeader(AuthFilter.SESSION_EXPIRES_AT_HEADER),
                "必须告知当前空闲失效时间");
        assertNotNull(res.getHeader(AuthFilter.SESSION_ABSOLUTE_EXPIRES_AT_HEADER),
                "必须告知绝对上限");
        assertNotNull(res.getHeader(AuthFilter.SESSION_MAX_AGE_HEADER),
                "必须告知剩余可用秒数");
        assertNotNull(res.getHeader("Set-Cookie"), "Cookie 有效期应随滑动顺延");
        log.info("decision: sliding headers emitted expiresAt={} absolute={} maxAge={}",
                res.getHeader(AuthFilter.SESSION_EXPIRES_AT_HEADER),
                res.getHeader(AuthFilter.SESSION_ABSOLUTE_EXPIRES_AT_HEADER),
                res.getHeader(AuthFilter.SESSION_MAX_AGE_HEADER));
    }
}
