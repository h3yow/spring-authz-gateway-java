package com.github.h3yow.springauthzgatewayjava.web;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.Cookie;
import java.util.ArrayList;
import java.util.List;
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
 * 凭据生命周期端到端：自助管理（列举/撤销单个/撤销其他）、滑动续期响应头、
 * 失效旧凭据不拖累公开入口与另一类有效凭据、401 细分原因可区分。
 * 每个用例使用独立 User-Agent 与来源 IP，避免共享上下文相互影响。
 */
@SpringBootTest
@AutoConfigureMockMvc
class CredentialLifecycleIntegrationTest {

    private static final Logger log = LoggerFactory.getLogger(CredentialLifecycleIntegrationTest.class);

    @Autowired
    private MockMvc mvc;
    private final ObjectMapper om = new ObjectMapper();

    private record Credentials(String sessionId, String csrf, String accessToken, String refreshToken) {}

    private Credentials login(String username, String password, String ip, String userAgent) throws Exception {
        MvcResult r = mvc.perform(post("/api/auth/login")
                        .header("X-Forwarded-For", ip)
                        .header("User-Agent", userAgent)
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

    private JsonNode listCredentials(String accessToken) throws Exception {
        MvcResult r = mvc.perform(get("/api/auth/credentials")
                        .header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andReturn();
        return om.readTree(r.getResponse().getContentAsString());
    }

    /** 按客户端标识过滤（共享上下文下隔离其他用例产生的凭据）。 */
    private static List<JsonNode> byClient(JsonNode list, String client) {
        List<JsonNode> matched = new ArrayList<>();
        for (JsonNode v : list) {
            if (client.equals(v.get("client").asText())) {
                matched.add(v);
            }
        }
        return matched;
    }

    @Test
    void credentialsEndpointRequiresAuthentication() throws Exception {
        MvcResult r = mvc.perform(get("/api/auth/credentials"))
                .andExpect(status().isUnauthorized()).andReturn();
        String body = r.getResponse().getContentAsString();
        log.info("input: GET /api/auth/credentials without credentials -> {}", body);
        assertTrue(body.contains("UNAUTHENTICATED"));
        assertTrue(body.contains("NO_CREDENTIALS"), "未携带凭据必须可区分");
    }

    @Test
    void listedCredentialsExposeMetadataButNoSecrets() throws Exception {
        Credentials c = login("alice", "alice-pass-123", "10.30.0.1", "lifecycle-list-agent");
        MvcResult r = mvc.perform(get("/api/auth/credentials")
                        .header("Authorization", "Bearer " + c.accessToken()))
                .andExpect(status().isOk()).andReturn();
        String body = r.getResponse().getContentAsString();
        JsonNode list = om.readTree(body);
        log.info("input: list credentials -> {}", body);
        List<JsonNode> mine = byClient(list, "lifecycle-list-agent");
        assertEquals(2, mine.size(), "一次登录应产生会话与刷新令牌两个凭据");
        for (JsonNode v : mine) {
            assertTrue(v.hasNonNull("credentialId"));
            assertTrue(v.hasNonNull("kind"));
            assertTrue(v.hasNonNull("issuedAt"));
            assertTrue(v.hasNonNull("lastUsedAt"));
            assertTrue(v.hasNonNull("expiresAt"));
            assertEquals("lifecycle-list-agent", v.get("client").asText());
        }
        assertFalse(body.contains(c.sessionId()), "列表不得包含会话标识原文");
        assertFalse(body.contains(c.accessToken()), "列表不得包含访问令牌原文");
        assertFalse(body.contains(c.refreshToken()), "列表不得包含刷新令牌原文");
        assertFalse(body.contains(c.csrf()), "列表不得包含 CSRF 令牌原文");
    }

    @Test
    void revokeOneCredentialLeavesOthersUsable() throws Exception {
        Credentials c1 = login("alice", "alice-pass-123", "10.30.0.2", "lifecycle-revoke-one-a");
        Credentials c2 = login("alice", "alice-pass-123", "10.30.0.3", "lifecycle-revoke-one-b");
        // 找到 c1 的会话凭据并撤销（用 c2 的令牌执行管理操作）
        String target = byClient(listCredentials(c2.accessToken()), "lifecycle-revoke-one-a")
                .stream().filter(v -> "SESSION".equals(v.get("kind").asText()))
                .findFirst().orElseThrow().get("credentialId").asText();
        mvc.perform(delete("/api/auth/credentials/" + target)
                        .header("Authorization", "Bearer " + c2.accessToken()))
                .andExpect(status().isNoContent());
        // 被撤销会话立即失效，且判定为"已撤销"
        MvcResult revoked = mvc.perform(get("/api/user/profile")
                        .cookie(new Cookie("SESSION", c1.sessionId())))
                .andExpect(status().isUnauthorized()).andReturn();
        log.info("input: use revoked session -> {}", revoked.getResponse().getContentAsString());
        assertTrue(revoked.getResponse().getContentAsString().contains("CREDENTIAL_REVOKED"));
        // 其他客户端不受影响
        mvc.perform(get("/api/user/profile").cookie(new Cookie("SESSION", c2.sessionId())))
                .andExpect(status().isOk());
        mvc.perform(get("/api/user/profile").header("Authorization", "Bearer " + c1.accessToken()))
                .andExpect(status().isOk());
        log.info("decision: revoked session=401 CREDENTIAL_REVOKED, other session=200, c1 token=200");
    }

    @Test
    void revokeOthersKeepsOnlyCurrentCredential() throws Exception {
        Credentials current = login("alice", "alice-pass-123", "10.30.0.4", "lifecycle-revoke-others");
        Credentials other = login("alice", "alice-pass-123", "10.30.0.5", "lifecycle-revoke-others");
        // 用 current 的会话（+CSRF）撤销其他全部
        mvc.perform(post("/api/auth/credentials/revoke-others")
                        .cookie(new Cookie("SESSION", current.sessionId()))
                        .header("X-CSRF-Token", current.csrf()))
                .andExpect(status().isNoContent());
        // 其他客户端的会话与令牌立即失效
        MvcResult otherSession = mvc.perform(get("/api/user/profile")
                        .cookie(new Cookie("SESSION", other.sessionId())))
                .andExpect(status().isUnauthorized()).andReturn();
        mvc.perform(get("/api/user/profile").header("Authorization", "Bearer " + other.accessToken()))
                .andExpect(status().isUnauthorized());
        mvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + other.refreshToken() + "\"}"))
                .andExpect(status().isUnauthorized());
        // 当前凭据不受影响
        mvc.perform(get("/api/user/profile").cookie(new Cookie("SESSION", current.sessionId())))
                .andExpect(status().isOk());
        log.info("input: revoke-others -> other session {} , current session=200",
                otherSession.getResponse().getContentAsString());
        assertTrue(otherSession.getResponse().getContentAsString().contains("CREDENTIAL_REVOKED"));
    }

    @Test
    void sessionRenewalIsVisibleToClient() throws Exception {
        Credentials c = login("alice", "alice-pass-123", "10.30.0.6", "lifecycle-renewal");
        MvcResult r = mvc.perform(get("/api/user/profile")
                        .cookie(new Cookie("SESSION", c.sessionId())))
                .andExpect(status().isOk()).andReturn();
        String expiresAt = r.getResponse().getHeader("X-Session-Expires-At");
        String renewed = r.getResponse().getHeader("X-Session-Renewed");
        log.info("input: session request -> X-Session-Expires-At={} X-Session-Renewed={}",
                expiresAt, renewed);
        assertNotNull(expiresAt, "客户端必须能感知会话失效时间");
        assertNotNull(renewed, "客户端必须能感知本次是否续期");
        // Bearer 请求不携带会话续期头
        MvcResult bearer = mvc.perform(get("/api/user/profile")
                        .header("Authorization", "Bearer " + c.accessToken()))
                .andExpect(status().isOk()).andReturn();
        assertNull(bearer.getResponse().getHeader("X-Session-Expires-At"));
    }

    @Test
    void staleSessionCookieDoesNotDragDownValidBearer() throws Exception {
        Credentials c = login("alice", "alice-pass-123", "10.30.0.7", "lifecycle-stale");
        // 撤销会话（用令牌执行管理操作），留下"旧会话 Cookie"
        String sessionCredential = byClient(listCredentials(c.accessToken()), "lifecycle-stale")
                .stream().filter(v -> "SESSION".equals(v.get("kind").asText()))
                .findFirst().orElseThrow().get("credentialId").asText();
        mvc.perform(delete("/api/auth/credentials/" + sessionCredential)
                        .header("Authorization", "Bearer " + c.accessToken()))
                .andExpect(status().isNoContent());
        // 携带失效会话 Cookie + 有效 Bearer 的改变状态请求：不得被旧凭据拖累（无需 CSRF）
        mvc.perform(post("/api/user/profile")
                        .cookie(new Cookie("SESSION", c.sessionId()))
                        .header("Authorization", "Bearer " + c.accessToken()))
                .andExpect(status().isOk());
        log.info("decision: stale session cookie + valid bearer POST -> 200 (no CSRF required)");
    }

    @Test
    void staleCredentialsDoNotBlockPublicEntryPoints() throws Exception {
        Credentials c = login("alice", "alice-pass-123", "10.30.0.8", "lifecycle-public");
        // 登出使凭据失效
        mvc.perform(post("/api/auth/logout")
                        .cookie(new Cookie("SESSION", c.sessionId()))
                        .header("X-CSRF-Token", c.csrf()))
                .andExpect(status().isNoContent());
        // 携带失效会话 Cookie 访问公开资源
        mvc.perform(get("/api/public/info").cookie(new Cookie("SESSION", c.sessionId())))
                .andExpect(status().isOk());
        // 携带失效会话 Cookie 重新登录
        mvc.perform(post("/api/auth/login")
                        .cookie(new Cookie("SESSION", c.sessionId()))
                        .header("X-Forwarded-For", "10.30.0.9")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"alice\",\"password\":\"alice-pass-123\"}"))
                .andExpect(status().isOk());
        // 携带失效会话 Cookie + 失效访问令牌，但刷新另一有效会话的刷新令牌
        Credentials fresh = login("alice", "alice-pass-123", "10.30.0.10", "lifecycle-public");
        mvc.perform(post("/api/auth/refresh")
                        .cookie(new Cookie("SESSION", c.sessionId()))
                        .header("Authorization", "Bearer " + c.accessToken())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + fresh.refreshToken() + "\"}"))
                .andExpect(status().isOk());
        log.info("decision: stale credentials did not block public info / re-login / refresh");
    }

    @Test
    void unauthenticatedReasonsAreDistinguishable() throws Exception {
        // 没有凭据
        MvcResult none = mvc.perform(get("/api/user/profile"))
                .andExpect(status().isUnauthorized()).andReturn();
        assertTrue(none.getResponse().getContentAsString().contains("NO_CREDENTIALS"));
        // 已撤销（或从未有效）凭据
        MvcResult revoked = mvc.perform(get("/api/user/profile")
                        .cookie(new Cookie("SESSION", "definitely-not-a-session")))
                .andExpect(status().isUnauthorized()).andReturn();
        assertTrue(revoked.getResponse().getContentAsString().contains("CREDENTIAL_REVOKED"));
        assertFalse(revoked.getResponse().getContentAsString().contains("definitely-not-a-session"),
                "错误响应不得包含凭据原文");
        log.info("input: no credential -> {}; revoked credential -> {}",
                none.getResponse().getContentAsString(), revoked.getResponse().getContentAsString());
    }
}
