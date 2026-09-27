package com.github.h3yow.springauthzgatewayjava.web;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

/**
 * 端到端集成测试：越权、撤销、CSRF、CORS、限流锁定。
 * 每个用例打印输入与判定依据；锁定相关用例使用独立来源 IP 避免相互影响。
 */
@SpringBootTest
@AutoConfigureMockMvc
class SecurityIntegrationTest {

    private static final Logger log = LoggerFactory.getLogger(SecurityIntegrationTest.class);

    @Autowired
    private MockMvc mvc;
    private final ObjectMapper om = new ObjectMapper();

    private record Credentials(String sessionId, String csrf, String accessToken, String refreshToken) {}

    private Credentials login(String username, String password, String ip) throws Exception {
        MvcResult r = mvc.perform(post("/api/auth/login")
                        .header("X-Forwarded-For", ip)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + username + "\",\"password\":\"" + password + "\"}"))
                .andExpect(status().isOk())
                .andReturn();
        JsonNode body = om.readTree(r.getResponse().getContentAsString());
        String setCookie = r.getResponse().getHeader("Set-Cookie");
        String sessionId = setCookie.split(";")[0].substring("SESSION=".length());
        return new Credentials(sessionId, r.getResponse().getHeader("X-CSRF-Token"),
                body.get("accessToken").asText(), body.get("refreshToken").asText());
    }

    @Test
    void unauthenticatedVsForbiddenAreDistinguished() throws Exception {
        MvcResult unauth = mvc.perform(get("/api/user/profile")).andExpect(status().isUnauthorized()).andReturn();
        log.info("input: GET /api/user/profile without credentials -> {} {}",
                unauth.getResponse().getStatus(), unauth.getResponse().getContentAsString());
        assertTrue(unauth.getResponse().getContentAsString().contains("CREDENTIAL_MISSING"),
                "未携带凭据应稳定判定为 CREDENTIAL_MISSING");

        Credentials alice = login("alice", "alice-pass-123", "10.20.0.1");
        MvcResult forbidden = mvc.perform(get("/api/admin/stats")
                        .header("Authorization", "Bearer " + alice.accessToken()))
                .andExpect(status().isForbidden()).andReturn();
        log.info("input: GET /api/admin/stats as alice(USER) -> {} {}",
                forbidden.getResponse().getStatus(), forbidden.getResponse().getContentAsString());
        assertTrue(forbidden.getResponse().getContentAsString().contains("FORBIDDEN_ROLE"));
        assertNotEquals(unauth.getResponse().getStatus(), forbidden.getResponse().getStatus(),
                "未认证(401)与未授权(403)必须区分");
    }

    @Test
    void adminCanAccessAdminResource() throws Exception {
        Credentials admin = login("admin", "admin-pass-123", "10.20.0.2");
        mvc.perform(get("/api/admin/stats").header("Authorization", "Bearer " + admin.accessToken()))
                .andExpect(status().isOk());
        log.info("input: GET /api/admin/stats as admin -> 200");
    }

    @Test
    void revokedSessionAndTokenAreRejectedEverywhere() throws Exception {
        Credentials c = login("alice", "alice-pass-123", "10.20.0.3");
        // 撤销前两种凭据均可用
        mvc.perform(get("/api/user/profile").cookie(new Cookie("SESSION", c.sessionId())))
                .andExpect(status().isOk());
        mvc.perform(get("/api/user/profile").header("Authorization", "Bearer " + c.accessToken()))
                .andExpect(status().isOk());
        // 登出（会话类改变状态请求需 CSRF 令牌）
        mvc.perform(post("/api/auth/logout")
                        .cookie(new Cookie("SESSION", c.sessionId()))
                        .header("X-CSRF-Token", c.csrf()))
                .andExpect(status().isNoContent());
        // 撤销后两种入口均拒绝
        MvcResult s = mvc.perform(get("/api/user/profile").cookie(new Cookie("SESSION", c.sessionId())))
                .andExpect(status().isUnauthorized()).andReturn();
        MvcResult t = mvc.perform(get("/api/user/profile").header("Authorization", "Bearer " + c.accessToken()))
                .andExpect(status().isUnauthorized()).andReturn();
        log.info("input: revoked session -> {}; revoked token -> {}",
                s.getResponse().getStatus(), t.getResponse().getStatus());
        assertTrue(t.getResponse().getContentAsString().contains("CREDENTIAL_REVOKED"),
                "已撤销凭据应稳定判定为 CREDENTIAL_REVOKED");
    }

    @Test
    void csrfRequiredForSessionStateChangeButNotForBearer() throws Exception {
        Credentials c = login("alice", "alice-pass-123", "10.20.0.4");
        // 会话 + 无 CSRF -> 403 CSRF_TOKEN_INVALID
        MvcResult noCsrf = mvc.perform(post("/api/user/profile").cookie(new Cookie("SESSION", c.sessionId())))
                .andExpect(status().isForbidden()).andReturn();
        log.info("input: POST /api/user/profile via session without CSRF -> {}",
                noCsrf.getResponse().getContentAsString());
        assertTrue(noCsrf.getResponse().getContentAsString().contains("CSRF_TOKEN_INVALID"));
        // 会话 + 错误 CSRF -> 403
        mvc.perform(post("/api/user/profile")
                        .cookie(new Cookie("SESSION", c.sessionId()))
                        .header("X-CSRF-Token", "wrong-token"))
                .andExpect(status().isForbidden());
        // 会话 + 正确 CSRF -> 200
        mvc.perform(post("/api/user/profile")
                        .cookie(new Cookie("SESSION", c.sessionId()))
                        .header("X-CSRF-Token", c.csrf()))
                .andExpect(status().isOk());
        // Bearer 无需 CSRF
        mvc.perform(post("/api/user/profile").header("Authorization", "Bearer " + c.accessToken()))
                .andExpect(status().isOk());
        log.info("decision: session+csrf=200, bearer without csrf=200, session without csrf=403");
    }

    @Test
    void corsPreflightAllowedOnlyForDeclaredOrigins() throws Exception {
        MvcResult ok = mvc.perform(options("/api/user/profile")
                        .header("Origin", "http://localhost:3000")
                        .header("Access-Control-Request-Method", "POST")
                        .header("Access-Control-Request-Headers", "x-csrf-token"))
                .andExpect(status().isOk()).andReturn();
        log.info("input: preflight origin=http://localhost:3000 -> ACAO={}",
                ok.getResponse().getHeader("Access-Control-Allow-Origin"));
        assertEquals("http://localhost:3000", ok.getResponse().getHeader("Access-Control-Allow-Origin"));

        MvcResult evil = mvc.perform(options("/api/user/profile")
                        .header("Origin", "http://evil.example")
                        .header("Access-Control-Request-Method", "POST"))
                .andExpect(status().isForbidden()).andReturn();
        log.info("input: preflight origin=http://evil.example -> status={} ACAO={}",
                evil.getResponse().getStatus(), evil.getResponse().getHeader("Access-Control-Allow-Origin"));
        assertNull(evil.getResponse().getHeader("Access-Control-Allow-Origin"),
                "未声明来源不得放行");
    }

    @Test
    void loginLockoutBlocksEvenCorrectPassword() throws Exception {
        String ip = "10.20.0.5";
        for (int i = 1; i <= 5; i++) {
            MvcResult r = mvc.perform(post("/api/auth/login")
                            .header("X-Forwarded-For", ip)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"username\":\"alice\",\"password\":\"wrong-" + i + "\"}"))
                    .andExpect(status().isUnauthorized()).andReturn();
            assertTrue(r.getResponse().getContentAsString().contains("INVALID_CREDENTIALS"),
                    "失败原因对外统一，不泄露账号是否存在");
        }
        MvcResult locked = mvc.perform(post("/api/auth/login")
                        .header("X-Forwarded-For", ip)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"alice\",\"password\":\"alice-pass-123\"}"))
                .andExpect(status().isTooManyRequests()).andReturn();
        log.info("input: correct password after 5 failures -> {} {}",
                locked.getResponse().getStatus(), locked.getResponse().getContentAsString());
        assertTrue(locked.getResponse().getContentAsString().contains("ACCOUNT_LOCKED"),
                "锁定期间即使凭据正确也不得通过");
        assertNotNull(locked.getResponse().getHeader("Retry-After"));
    }

    @Test
    void failedAttemptsDoNotPolluteExistingSession() throws Exception {
        Credentials c = login("alice", "alice-pass-123", "10.20.0.6");
        mvc.perform(post("/api/auth/login")
                        .header("X-Forwarded-For", "10.20.0.7")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"alice\",\"password\":\"wrong\"}"))
                .andExpect(status().isUnauthorized());
        mvc.perform(get("/api/user/profile").header("Authorization", "Bearer " + c.accessToken()))
                .andExpect(status().isOk());
        log.info("decision: failed login did not affect existing token -> 200");
    }

    @Test
    void refreshTokenRotationOverHttp() throws Exception {
        Credentials c = login("alice", "alice-pass-123", "10.20.0.8");
        MvcResult ok = mvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + c.refreshToken() + "\"}"))
                .andExpect(status().isOk()).andReturn();
        log.info("input: refresh once -> 200");
        MvcResult reuse = mvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + c.refreshToken() + "\"}"))
                .andExpect(status().isUnauthorized()).andReturn();
        log.info("input: reuse same refresh token -> {}", reuse.getResponse().getContentAsString());
        // 新访问令牌可用
        JsonNode body = om.readTree(ok.getResponse().getContentAsString());
        mvc.perform(get("/api/user/profile")
                        .header("Authorization", "Bearer " + body.get("accessToken").asText()))
                .andExpect(status().isOk());
    }

    @Test
    void undeclaredResourceDefaultsToDeny() throws Exception {
        Credentials admin = login("admin", "admin-pass-123", "10.20.0.9");
        MvcResult r = mvc.perform(get("/api/undeclared")
                        .header("Authorization", "Bearer " + admin.accessToken()))
                .andExpect(status().isForbidden()).andReturn();
        log.info("input: GET /api/undeclared as admin -> {}", r.getResponse().getContentAsString());
        assertTrue(r.getResponse().getContentAsString().contains("FORBIDDEN_RESOURCE"),
                "缺省策略必须为拒绝");
    }

    @Test
    void errorResponsesContainCorrelationIdButNoSecrets() throws Exception {
        Credentials c = login("alice", "alice-pass-123", "10.20.0.10");
        mvc.perform(post("/api/auth/logout")
                        .cookie(new Cookie("SESSION", c.sessionId()))
                        .header("X-CSRF-Token", c.csrf()))
                .andExpect(status().isNoContent());
        MvcResult r = mvc.perform(get("/api/user/profile").cookie(new Cookie("SESSION", c.sessionId())))
                .andExpect(status().isUnauthorized()).andReturn();
        String body = r.getResponse().getContentAsString();
        log.info("input: request with revoked session -> {}", body);
        assertTrue(body.contains("correlationId"), "错误响应需含关联标识");
        assertFalse(body.contains(c.sessionId()), "错误响应不得包含会话标识原文");
        assertFalse(body.contains(c.accessToken()), "错误响应不得包含令牌原文");
        assertNotNull(r.getResponse().getHeader("X-Correlation-Id"));
    }

    // ---- 本轮新增：活跃凭据自助管理 ----

    @Test
    void credentialSelfServiceListRevokeOneAndRevokeOthers() throws Exception {
        Credentials c1 = login("alice", "alice-pass-123", "10.30.0.1");
        Credentials c2 = login("alice", "alice-pass-123", "10.30.0.2");

        // 列表：两个客户端的会话 + 访问令牌共 4 条，且不含任何凭据原文
        MvcResult list = mvc.perform(get("/api/user/credentials")
                        .cookie(new Cookie("SESSION", c1.sessionId())))
                .andExpect(status().isOk()).andReturn();
        String listBody = list.getResponse().getContentAsString();
        JsonNode entries = om.readTree(listBody);
        // 共享上下文里可能有其他用例签发的凭据，按本用例专属客户端来源过滤
        java.util.List<JsonNode> mine = new java.util.ArrayList<>();
        entries.forEach(e -> {
            String ck = e.get("clientKey").asText();
            if (ck.equals("10.30.0.1") || ck.equals("10.30.0.2")) {
                mine.add(e);
            }
        });
        log.info("input: GET /api/user/credentials -> total={} mine={}", entries.size(), mine.size());
        assertEquals(4, mine.size(), "两个客户端各一个会话 + 一个访问令牌");
        for (JsonNode e : mine) {
            assertNotNull(e.get("id"));
            assertNotNull(e.get("clientKey"));
            assertNotNull(e.get("issuedAt"));
            assertNotNull(e.get("lastUsedAt"));
            assertNotNull(e.get("expiresAt"));
        }
        assertFalse(listBody.contains(c1.sessionId()), "列表不得包含会话原文");
        assertFalse(listBody.contains(c1.accessToken()), "列表不得包含令牌原文");
        assertFalse(listBody.contains(c1.refreshToken()), "列表不得包含刷新令牌原文");

        // 撤销单个会话凭据：恰好一个会话失效，其余不受影响
        String sessionHandle = null;
        for (JsonNode e : mine) {
            if ("SESSION".equals(e.get("kind").asText())) {
                sessionHandle = e.get("id").asText();
                break;
            }
        }
        mvc.perform(post("/api/user/credentials/revoke")
                        .cookie(new Cookie("SESSION", c1.sessionId()))
                        .header("X-CSRF-Token", c1.csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"id\":\"" + sessionHandle + "\"}"))
                .andExpect(status().isOk());
        boolean s1Alive = mvc.perform(get("/api/user/profile")
                        .cookie(new Cookie("SESSION", c1.sessionId())))
                .andReturn().getResponse().getStatus() == 200;
        boolean s2Alive = mvc.perform(get("/api/user/profile")
                        .cookie(new Cookie("SESSION", c2.sessionId())))
                .andReturn().getResponse().getStatus() == 200;
        log.info("decision: after single revoke s1Alive={} s2Alive={}", s1Alive, s2Alive);
        assertTrue(s1Alive != s2Alive, "撤销单个凭据必须恰好影响一个会话");
        mvc.perform(get("/api/user/profile").header("Authorization", "Bearer " + c1.accessToken()))
                .andExpect(status().isOk());
        mvc.perform(get("/api/user/profile").header("Authorization", "Bearer " + c2.accessToken()))
                .andExpect(status().isOk());

        // 用幸存会话撤销其余全部：只剩当前会话
        Credentials survivor = s1Alive ? c1 : c2;
        Credentials victim = s1Alive ? c2 : c1;
        mvc.perform(post("/api/user/credentials/revoke-others")
                        .cookie(new Cookie("SESSION", survivor.sessionId()))
                        .header("X-CSRF-Token", survivor.csrf()))
                .andExpect(status().isOk());
        mvc.perform(get("/api/user/profile").cookie(new Cookie("SESSION", survivor.sessionId())))
                .andExpect(status().isOk());
        mvc.perform(get("/api/user/profile").cookie(new Cookie("SESSION", victim.sessionId())))
                .andExpect(status().isUnauthorized());
        mvc.perform(get("/api/user/profile").header("Authorization", "Bearer " + c1.accessToken()))
                .andExpect(status().isUnauthorized());
        mvc.perform(get("/api/user/profile").header("Authorization", "Bearer " + c2.accessToken()))
                .andExpect(status().isUnauthorized());

        MvcResult after = mvc.perform(get("/api/user/credentials")
                        .cookie(new Cookie("SESSION", survivor.sessionId())))
                .andExpect(status().isOk()).andReturn();
        assertEquals(1, om.readTree(after.getResponse().getContentAsString()).size(),
                "撤销其余全部后应只剩当前凭据");
        log.info("decision: revoke-others kept exactly the current session");
    }

    @Test
    void revokeOthersViaBearerKeepsCurrentTokenUsable() throws Exception {
        Credentials c1 = login("alice", "alice-pass-123", "10.30.0.3");
        Credentials c2 = login("alice", "alice-pass-123", "10.30.0.4");

        // Bearer 方式调用撤销其余全部（无需 CSRF），当前访问令牌保持可用
        mvc.perform(post("/api/user/credentials/revoke-others")
                        .header("Authorization", "Bearer " + c1.accessToken()))
                .andExpect(status().isOk());
        mvc.perform(get("/api/user/profile").header("Authorization", "Bearer " + c1.accessToken()))
                .andExpect(status().isOk());
        mvc.perform(get("/api/user/profile").cookie(new Cookie("SESSION", c1.sessionId())))
                .andExpect(status().isUnauthorized());
        mvc.perform(get("/api/user/profile").cookie(new Cookie("SESSION", c2.sessionId())))
                .andExpect(status().isUnauthorized());
        mvc.perform(get("/api/user/profile").header("Authorization", "Bearer " + c2.accessToken()))
                .andExpect(status().isUnauthorized());
        // 当前客户端仍可用自己的刷新令牌续期
        mvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + c1.refreshToken() + "\"}"))
                .andExpect(status().isOk());
        log.info("decision: bearer revoke-others kept current token pair usable only");
    }

    // ---- 本轮新增：失效旧凭据不拖累既有入口，两类凭据彼此独立 ----

    @Test
    void staleCredentialDoesNotDragDownPublicLoginOrOtherValidCredential() throws Exception {
        Credentials stale = login("alice", "alice-pass-123", "10.30.0.5");
        // 登出使该会话与全部令牌失效（成为"旧凭据"）
        mvc.perform(post("/api/auth/logout")
                        .cookie(new Cookie("SESSION", stale.sessionId()))
                        .header("X-CSRF-Token", stale.csrf()))
                .andExpect(status().isNoContent());

        // 携带失效旧凭据访问公开资源：不受影响
        mvc.perform(get("/api/public/info").cookie(new Cookie("SESSION", stale.sessionId())))
                .andExpect(status().isOk());
        // 携带失效旧凭据重新登录：不受影响
        MvcResult relogin = mvc.perform(post("/api/auth/login")
                        .cookie(new Cookie("SESSION", stale.sessionId()))
                        .header("X-Forwarded-For", "10.30.0.5")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"alice\",\"password\":\"alice-pass-123\"}"))
                .andExpect(status().isOk()).andReturn();
        log.info("input: stale session cookie on public/login endpoints -> both 200");

        // 携带失效会话 Cookie + 有效 Bearer 做改变状态请求：Bearer 正常生效，不被 CSRF 拦截
        String freshAccess = om.readTree(relogin.getResponse().getContentAsString())
                .get("accessToken").asText();
        mvc.perform(post("/api/user/profile")
                        .cookie(new Cookie("SESSION", stale.sessionId()))
                        .header("Authorization", "Bearer " + freshAccess))
                .andExpect(status().isOk());
        log.info("decision: stale session cookie did not break valid bearer state change");

        // 反向：有效会话 + 失效旧 Bearer，会话照常可用
        Credentials fresh = login("alice", "alice-pass-123", "10.30.0.6");
        mvc.perform(get("/api/user/profile")
                        .cookie(new Cookie("SESSION", fresh.sessionId()))
                        .header("Authorization", "Bearer " + stale.accessToken()))
                .andExpect(status().isOk());
        log.info("decision: valid session not dragged down by stale bearer");
    }

    @Test
    void forgedBearerYieldsCredentialInvalidOverHttp() throws Exception {
        MvcResult r = mvc.perform(get("/api/user/profile")
                        .header("Authorization", "Bearer forged.token.value"))
                .andExpect(status().isUnauthorized()).andReturn();
        log.info("input: forged bearer -> {}", r.getResponse().getContentAsString());
        assertTrue(r.getResponse().getContentAsString().contains("CREDENTIAL_INVALID"),
                "不被认可的凭据应稳定判定为 CREDENTIAL_INVALID");
    }

    @Test
    void sessionRequestsCarrySlidingRenewalHeaders() throws Exception {
        Credentials c = login("alice", "alice-pass-123", "10.30.0.7");
        MvcResult r = mvc.perform(get("/api/user/profile")
                        .cookie(new Cookie("SESSION", c.sessionId())))
                .andExpect(status().isOk()).andReturn();
        assertNotNull(r.getResponse().getHeader("X-Session-Expires-At"), "必须告知空闲失效时间");
        assertNotNull(r.getResponse().getHeader("X-Session-Absolute-Expires-At"), "必须告知绝对上限");
        assertNotNull(r.getResponse().getHeader("X-Session-Max-Age"), "必须告知剩余秒数");
        log.info("decision: sliding headers present expiresAt={} absolute={}",
                r.getResponse().getHeader("X-Session-Expires-At"),
                r.getResponse().getHeader("X-Session-Absolute-Expires-At"));
    }
}
