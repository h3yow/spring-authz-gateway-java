package com.github.h3yow.springauthzgatewayjava.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

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

@SpringBootTest
@AutoConfigureMockMvc
class WebIntegrationTest {

    private static final Logger log = LoggerFactory.getLogger(WebIntegrationTest.class);

    @Autowired
    private MockMvc mvc;

    private final ObjectMapper mapper = new ObjectMapper();

    private record Session(String sessionId, String csrfToken) {
    }

    private Session login(String username, String password) throws Exception {
        MvcResult result = mvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + username + "\",\"password\":\"" + password + "\"}"))
                .andExpect(status().isOk())
                .andReturn();
        String setCookie = result.getResponse().getHeader("Set-Cookie");
        String sessionId = setCookie.split(";")[0].split("=")[1];
        String csrf = mapper.readTree(result.getResponse().getContentAsString()).get("csrfToken").asText();
        log.info("login user={} -> session=<masked> csrf=<masked>", username);
        return new Session(sessionId, csrf);
    }

    @Test
    void unauthenticatedGets401WithStableCode() throws Exception {
        MvcResult result = mvc.perform(get("/api/me"))
                .andExpect(status().isUnauthorized())
                .andReturn();
        JsonNode body = mapper.readTree(result.getResponse().getContentAsString());
        log.info("input=GET /api/me anonymous -> code={} cid={}", body.get("code").asText(), body.get("correlationId").asText());
        assertEquals("UNAUTHENTICATED", body.get("code").asText());
        assertNotNull(body.get("correlationId").asText());
    }

    @Test
    void sessionLoginThenAccessProfile() throws Exception {
        Session session = login("bob", "bob-pass-123");
        MvcResult result = mvc.perform(get("/api/me").cookie(new Cookie("SESSION", session.sessionId())))
                .andExpect(status().isOk())
                .andReturn();
        JsonNode body = mapper.readTree(result.getResponse().getContentAsString());
        log.info("input=GET /api/me as bob -> username={} kind={}",
                body.get("username").asText(), body.get("credentialKind").asText());
        assertEquals("bob", body.get("username").asText());
        assertEquals("session", body.get("credentialKind").asText());
    }

    @Test
    void privilegeEscalationDeniedWith403() throws Exception {
        Session bob = login("bob", "bob-pass-123");
        MvcResult result = mvc.perform(get("/api/admin/stats").cookie(new Cookie("SESSION", bob.sessionId())))
                .andExpect(status().isForbidden())
                .andReturn();
        JsonNode body = mapper.readTree(result.getResponse().getContentAsString());
        log.info("input=GET /api/admin/stats as bob(USER) -> code={}", body.get("code").asText());
        assertEquals("INSUFFICIENT_ROLE", body.get("code").asText());
    }

    @Test
    void missingPermissionDeniedWith403() throws Exception {
        Session bob = login("bob", "bob-pass-123");
        MvcResult result = mvc.perform(post("/api/documents")
                        .cookie(new Cookie("SESSION", bob.sessionId()))
                        .header("X-CSRF-Token", bob.csrfToken()))
                .andExpect(status().isForbidden())
                .andReturn();
        JsonNode body = mapper.readTree(result.getResponse().getContentAsString());
        log.info("input=POST /api/documents as bob(USER, no documents:write) -> code={}", body.get("code").asText());
        assertEquals("MISSING_PERMISSION", body.get("code").asText());
    }

    @Test
    void adminCanWriteDocuments() throws Exception {
        Session alice = login("alice", "alice-pass-123");
        mvc.perform(post("/api/documents")
                        .cookie(new Cookie("SESSION", alice.sessionId()))
                        .header("X-CSRF-Token", alice.csrfToken()))
                .andExpect(status().isOk());
        log.info("input=POST /api/documents as alice(ADMIN) with csrf -> 200");
    }

    @Test
    void stateChangingRequestWithoutCsrfTokenRejected() throws Exception {
        Session alice = login("alice", "alice-pass-123");
        MvcResult result = mvc.perform(post("/api/documents")
                        .cookie(new Cookie("SESSION", alice.sessionId())))
                .andExpect(status().isForbidden())
                .andReturn();
        JsonNode body = mapper.readTree(result.getResponse().getContentAsString());
        log.info("input=POST /api/documents session-auth without CSRF -> code={}", body.get("code").asText());
        assertEquals("CSRF_TOKEN_INVALID", body.get("code").asText());
    }

    @Test
    void wrongCsrfTokenRejected() throws Exception {
        Session alice = login("alice", "alice-pass-123");
        MvcResult result = mvc.perform(post("/api/documents")
                        .cookie(new Cookie("SESSION", alice.sessionId()))
                        .header("X-CSRF-Token", "forged-token"))
                .andExpect(status().isForbidden())
                .andReturn();
        JsonNode body = mapper.readTree(result.getResponse().getContentAsString());
        log.info("input=POST with forged CSRF token -> code={}", body.get("code").asText());
        assertEquals("CSRF_TOKEN_INVALID", body.get("code").asText());
    }

    @Test
    void logoutInvalidatesSessionImmediately() throws Exception {
        Session bob = login("bob", "bob-pass-123");
        mvc.perform(post("/api/auth/logout")
                        .cookie(new Cookie("SESSION", bob.sessionId()))
                        .header("X-CSRF-Token", bob.csrfToken()))
                .andExpect(status().isOk());
        MvcResult after = mvc.perform(get("/api/me").cookie(new Cookie("SESSION", bob.sessionId())))
                .andExpect(status().isUnauthorized())
                .andReturn();
        JsonNode body = mapper.readTree(after.getResponse().getContentAsString());
        log.info("input=GET /api/me after logout -> code={}", body.get("code").asText());
        assertEquals("UNAUTHENTICATED", body.get("code").asText());
    }

    @Test
    void tokenFlowAndRevocation() throws Exception {
        MvcResult tokenResult = mvc.perform(post("/api/auth/token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"bob\",\"password\":\"bob-pass-123\"}"))
                .andExpect(status().isOk())
                .andReturn();
        JsonNode tokens = mapper.readTree(tokenResult.getResponse().getContentAsString());
        String accessToken = tokens.get("accessToken").asText();

        mvc.perform(get("/api/me").header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isOk());
        log.info("input=GET /api/me with bearer token -> 200");

        mvc.perform(post("/api/auth/token/revoke").header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isOk());
        MvcResult after = mvc.perform(get("/api/me").header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isUnauthorized())
                .andReturn();
        JsonNode body = mapper.readTree(after.getResponse().getContentAsString());
        log.info("input=GET /api/me after revoke -> code={}", body.get("code").asText());
        assertEquals("UNAUTHENTICATED", body.get("code").asText());
    }

    @Test
    void tokenRefreshRotation() throws Exception {
        MvcResult tokenResult = mvc.perform(post("/api/auth/token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"bob\",\"password\":\"bob-pass-123\"}"))
                .andExpect(status().isOk())
                .andReturn();
        JsonNode tokens = mapper.readTree(tokenResult.getResponse().getContentAsString());
        String refreshToken = tokens.get("refreshToken").asText();

        MvcResult refreshed = mvc.perform(post("/api/auth/token/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + refreshToken + "\"}"))
                .andExpect(status().isOk())
                .andReturn();
        String newAccess = mapper.readTree(refreshed.getResponse().getContentAsString())
                .get("accessToken").asText();
        mvc.perform(get("/api/me").header("Authorization", "Bearer " + newAccess))
                .andExpect(status().isOk());
        log.info("input=refresh rotation -> new access token works");

        MvcResult replay = mvc.perform(post("/api/auth/token/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + refreshToken + "\"}"))
                .andExpect(status().isUnauthorized())
                .andReturn();
        JsonNode body = mapper.readTree(replay.getResponse().getContentAsString());
        log.info("input=replay old refresh token -> code={}", body.get("code").asText());
        assertEquals("TOKEN_INVALID", body.get("code").asText());
    }

    @Test
    void loginFailureCodesDoNotRevealAccountExistence() throws Exception {
        MvcResult unknown = mvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"ghost\",\"password\":\"x\"}"))
                .andExpect(status().isUnauthorized())
                .andReturn();
        MvcResult wrongPass = mvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"bob\",\"password\":\"wrong\"}"))
                .andExpect(status().isUnauthorized())
                .andReturn();
        String codeUnknown = mapper.readTree(unknown.getResponse().getContentAsString()).get("code").asText();
        String codeWrong = mapper.readTree(wrongPass.getResponse().getContentAsString()).get("code").asText();
        log.info("input=unknown-user code={} | wrong-password code={}", codeUnknown, codeWrong);
        assertEquals("INVALID_CREDENTIALS", codeUnknown);
        assertEquals(codeUnknown, codeWrong, "两种失败对外必须不可区分");
    }

    @Test
    void declaredOriginPreflightAllowed() throws Exception {
        MvcResult result = mvc.perform(options("/api/me")
                        .header("Origin", "http://localhost:3000")
                        .header("Access-Control-Request-Method", "GET"))
                .andExpect(status().isOk())
                .andReturn();
        String acao = result.getResponse().getHeader("Access-Control-Allow-Origin");
        log.info("input=preflight origin=http://localhost:3000 -> ACAO={}", acao);
        assertEquals("http://localhost:3000", acao);
    }

    @Test
    void undeclaredOriginNotAllowed() throws Exception {
        MvcResult result = mvc.perform(options("/api/me")
                        .header("Origin", "https://evil.example.com")
                        .header("Access-Control-Request-Method", "GET"))
                .andReturn();
        String acao = result.getResponse().getHeader("Access-Control-Allow-Origin");
        log.info("input=preflight origin=https://evil.example.com -> ACAO={} status={}",
                acao, result.getResponse().getStatus());
        assertNull(acao, "未声明来源不得得到 CORS 许可");
    }

    @Test
    void errorResponsesNeverLeakSecrets() throws Exception {
        MvcResult result = mvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"bob\",\"password\":\"bob-pass-123-wrong\"}"))
                .andExpect(status().isUnauthorized())
                .andReturn();
        String body = result.getResponse().getContentAsString();
        log.info("error body={}", body);
        assertFalse(body.contains("bob-pass-123"), "错误响应不得包含口令");
        assertFalse(body.contains("SESSION"), "错误响应不得包含会话标识");
    }
}
