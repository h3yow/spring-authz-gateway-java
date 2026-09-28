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
        assertTrue(unauth.getResponse().getContentAsString().contains("UNAUTHENTICATED"));

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
        assertTrue(t.getResponse().getContentAsString().contains("UNAUTHENTICATED"));
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
        // 跨域前端必须能读到滑动续期感知头
        String exposed = ok.getResponse().getHeader("Access-Control-Expose-Headers");
        assertNotNull(exposed);
        assertTrue(exposed.contains(AuthFilter.SESSION_EXPIRES_AT_HEADER)
                        && exposed.contains(AuthFilter.SESSION_ABSOLUTE_EXPIRES_AT_HEADER)
                        && exposed.contains(AuthFilter.SESSION_RENEWED_HEADER),
                "续期感知头必须在 CORS Expose-Headers 中，跨域才可读: " + exposed);

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
}
