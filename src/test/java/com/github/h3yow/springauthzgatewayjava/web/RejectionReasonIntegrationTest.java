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
 * 401 三类拒绝原因在 HTTP 层的稳定性与可见性：
 * 同一过期凭据在重复请求、不同入口（用户资源/管理资源/凭据管理）上原因不漂移；
 * 续期感知头通过 CORS Access-Control-Expose-Headers 跨域可读；
 * 失效旧凭据与另一类有效凭据并存时收敛正确。
 */
@SpringBootTest(properties = {
        "auth.session-ttl=1s",
        "auth.access-token-ttl=1s"
})
@AutoConfigureMockMvc
class RejectionReasonIntegrationTest {

    private static final Logger log = LoggerFactory.getLogger(RejectionReasonIntegrationTest.class);

    @Autowired
    private MockMvc mvc;

    @Autowired
    private com.github.h3yow.springauthzgatewayjava.auth.SessionService sessionService;
    @Autowired
    private com.github.h3yow.springauthzgatewayjava.auth.TokenService tokenService;
    @Autowired
    private com.github.h3yow.springauthzgatewayjava.auth.CredentialManager credentialManager;

    private final ObjectMapper om = new ObjectMapper();

    private record Login(String sessionId, String csrf, String accessToken, String refreshToken) {}

    private Login login(String ip) throws Exception {
        MvcResult r = mvc.perform(post("/api/auth/login")
                        .header("X-Forwarded-For", ip)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"alice\",\"password\":\"alice-pass-123\"}"))
                .andExpect(status().isOk()).andReturn();
        JsonNode body = om.readTree(r.getResponse().getContentAsString());
        String sessionId = r.getResponse().getHeader("Set-Cookie")
                .split(";")[0].substring("SESSION=".length());
        return new Login(sessionId, r.getResponse().getHeader("X-CSRF-Token"),
                body.get("accessToken").asText(), body.get("refreshToken").asText());
    }

    private String reason(MvcResult r) throws Exception {
        return r.getResponse().getContentAsString();
    }

    @Test
    void expiredSessionReasonStableAcrossRepeatsAndEntryPoints() throws Exception {
        Login c = login("10.60.0.1");
        Thread.sleep(1200);
        List<String> paths = List.of("/api/user/profile", "/api/admin/stats",
                "/api/auth/credentials", "/api/user/profile", "/api/user/profile");
        String first = null;
        for (String path : paths) {
            MvcResult r = mvc.perform(get(path).cookie(new Cookie("SESSION", c.sessionId())))
                    .andExpect(status().isUnauthorized()).andReturn();
            String body = reason(r);
            log.info("expired session -> {} {}", path, body);
            assertTrue(body.contains("CREDENTIAL_EXPIRED"),
                    "过期会话在入口 " + path + " 必须稳定为 CREDENTIAL_EXPIRED，不得漂移");
            assertTrue(!body.contains(c.sessionId()), "响应不得包含会话标识原文");
            if (first == null) {
                first = extractReason(body);
            } else {
                assertEquals(first, extractReason(body), "同一凭据重复请求的 reason 字段必须一致");
            }
        }
    }

    @Test
    void noCredentialsAndRevokedReasonsStayStable() throws Exception {
        // 无凭据：重复稳定 NO_CREDENTIALS
        for (int i = 0; i < 3; i++) {
            MvcResult r = mvc.perform(get("/api/user/profile"))
                    .andExpect(status().isUnauthorized()).andReturn();
            assertTrue(reason(r).contains("NO_CREDENTIALS"));
        }
        // 已撤销会话：撤销后反复请求稳定 CREDENTIAL_REVOKED
        Login c = login("10.60.0.2");
        mvc.perform(post("/api/auth/logout")
                        .cookie(new Cookie("SESSION", c.sessionId()))
                        .header("X-CSRF-Token", c.csrf()))
                .andExpect(status().isNoContent());
        for (int i = 0; i < 5; i++) {
            MvcResult r = mvc.perform(get("/api/user/profile")
                            .cookie(new Cookie("SESSION", c.sessionId())))
                    .andExpect(status().isUnauthorized()).andReturn();
            String body = reason(r);
            assertTrue(body.contains("CREDENTIAL_REVOKED"),
                    "撤销后重复请求必须稳定为 CREDENTIAL_REVOKED，不得漂移为过期");
            assertFalse(body.contains(c.sessionId()), "响应不得包含凭据原文");
        }
    }

    @Test
    void sessionHeadersAreExposedForCors() throws Exception {
        Login c = login("10.60.0.3");
        MvcResult r = mvc.perform(get("/api/user/profile")
                        .header("Origin", "http://localhost:3000")
                        .cookie(new Cookie("SESSION", c.sessionId())))
                .andExpect(status().isOk()).andReturn();
        String exposed = r.getResponse().getHeader("Access-Control-Expose-Headers");
        assertNotNull(exposed, "合法跨域请求必须返回 Access-Control-Expose-Headers");
        assertTrue(exposed.contains("X-Session-Expires-At"), "续期失效时间头必须跨域可读");
        assertTrue(exposed.contains("X-Session-Renewed"), "续期是否发生头必须跨域可读");
        assertNotNull(r.getResponse().getHeader("X-Session-Expires-At"));
        assertNotNull(r.getResponse().getHeader("X-Session-Renewed"));
        log.info("CORS exposed headers: {}", exposed);
    }

    @Test
    void staleExpiredCookieWithValidBearerDoesNotChangeStateRequest() throws Exception {
        Login stale = login("10.60.0.4");
        Thread.sleep(1200); // stale 会话与令牌全部失效
        Login fresh = login("10.60.0.5");
        // 失效旧会话 Cookie + 新的有效 Bearer 做改变状态请求：成功、无需 CSRF、旧 Cookie 被清
        MvcResult r = mvc.perform(post("/api/user/profile")
                        .cookie(new Cookie("SESSION", stale.sessionId()))
                        .header("Authorization", "Bearer " + fresh.accessToken()))
                .andExpect(status().isOk()).andReturn();
        assertNotNull(r.getResponse().getHeaders("Set-Cookie").stream()
                .filter(sc -> sc.startsWith("SESSION=") && sc.contains("Max-Age=0"))
                .findFirst().orElse(null),
                "旧会话已失效，必须响应清除其 Cookie 且不影响 Bearer 的状态变更");
        // 失效旧 Bearer + 有效会话 Cookie 的 POST（带正确 CSRF）：同样成功
        MvcResult r2 = mvc.perform(post("/api/user/profile")
                        .cookie(new Cookie("SESSION", fresh.sessionId()))
                        .header("X-CSRF-Token", fresh.csrf())
                        .header("Authorization", "Bearer " + stale.accessToken()))
                .andExpect(status().isOk()).andReturn();
        log.info("mixed stale/valid credentials converged: {} / {}",
                r.getResponse().getStatus(), r2.getResponse().getStatus());
    }

    @Test
    void concurrentDuplicateRevokesConvergeAndOldCredentialCannotReinstate() throws Exception {
        Login victim = login("10.60.0.6");
        Login admin = login("10.60.0.7");
        // 找到 victim 自身的 SESSION 凭据公开标识
        MvcResult own = mvc.perform(get("/api/auth/credentials")
                        .header("Authorization", "Bearer " + victim.accessToken()))
                .andExpect(status().isOk()).andReturn();
        JsonNode ownNodes = om.readTree(own.getResponse().getContentAsString());
        String victimSessionCredential = null;
        for (JsonNode n : ownNodes) {
            if ("SESSION".equals(n.get("kind").asText())) {
                victimSessionCredential = n.get("credentialId").asText();
            }
        }
        assertNotNull(victimSessionCredential);
        final String targetCredential = victimSessionCredential;

        // 并发撤销冲击（服务层线程安全；MockMvc 响应对象非线程安全，故并发打在服务层）：
        // 单个撤销（门面）与直接会话撤销重复交错，全部必须收敛到同一个终态
        int n = 16;
        List<Thread> threads = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            final boolean viaManager = i % 2 == 0;
            threads.add(new Thread(() -> {
                if (viaManager) {
                    credentialManager.revokeOne("alice", targetCredential);
                } else {
                    sessionService.revoke(victim.sessionId());
                }
            }));
        }
        threads.forEach(Thread::start);
        for (Thread t : threads) {
            try {
                t.join(10000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            assertFalse(t.isAlive(), "撤销线程必须收敛结束");
        }

        // HTTP 层顺序验证：victim 会话稳定 401 CREDENTIAL_REVOKED，重复请求不漂移
        for (int i = 0; i < 3; i++) {
            MvcResult r = mvc.perform(get("/api/user/profile")
                            .cookie(new Cookie("SESSION", victim.sessionId())))
                    .andExpect(status().isUnauthorized()).andReturn();
            String body = reason(r);
            assertTrue(body.contains("CREDENTIAL_REVOKED"));
            assertFalse(body.contains(victim.sessionId()), "响应不得包含凭据原文");
        }
        // admin 自身不受 victim 撤销影响：用其 Bearer（刚签发）访问受保护资源成功
        mvc.perform(get("/api/user/profile")
                        .header("Authorization", "Bearer " + admin.accessToken()))
                .andExpect(status().isOk());
        // victim 的 Bearer 属于另一独立凭据（本次只撤销了它的会话）；撤销其令牌凭据
        final String victimTokenCredential = tokenService.credentialIdOf(victim.accessToken()).orElseThrow();
        credentialManager.revokeOne("alice", victimTokenCredential);

        mvc.perform(delete("/api/auth/credentials/" + targetCredential)
                        .header("Authorization", "Bearer " + admin.accessToken()))
                .andExpect(status().isNoContent()); // 幂等：再次撤销已撤销凭据
        mvc.perform(get("/api/user/profile")
                        .header("Authorization", "Bearer " + victim.accessToken()))
                .andExpect(status().isUnauthorized());
        mvc.perform(get("/api/user/profile")
                        .header("Authorization", "Bearer " + admin.accessToken()))
                .andExpect(status().isOk());

        // 已终态的 victim 会话再做"续期式"访问也不能复活
        mvc.perform(get("/api/user/profile").cookie(new Cookie("SESSION", victim.sessionId())))
                .andExpect(status().isUnauthorized());
        log.info("concurrent duplicate revoke converged to single terminal state");
    }

    private static String extractReason(String body) {
        int i = body.indexOf("\"reason\"");
        return body.substring(i, body.indexOf('}', i));
    }
}
