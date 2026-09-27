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
 * 过期凭据的 HTTP 级判定：401 响应细分原因必须为 CREDENTIAL_EXPIRED，
 * 与"没有凭据"（NO_CREDENTIALS）、"已撤销"（CREDENTIAL_REVOKED）稳定区分。
 * 使用 1s 超短有效期构造真实过期场景。
 */
@SpringBootTest(properties = {
        "auth.session-ttl=1s",
        "auth.access-token-ttl=1s"
})
@AutoConfigureMockMvc
class ExpiredCredentialIntegrationTest {

    private static final Logger log = LoggerFactory.getLogger(ExpiredCredentialIntegrationTest.class);

    @Autowired
    private MockMvc mvc;
    private final ObjectMapper om = new ObjectMapper();

    @Test
    void expiredSessionAndTokenAreReportedAsExpired() throws Exception {
        MvcResult login = mvc.perform(post("/api/auth/login")
                        .header("X-Forwarded-For", "10.40.0.1")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"alice\",\"password\":\"alice-pass-123\"}"))
                .andExpect(status().isOk()).andReturn();
        JsonNode body = om.readTree(login.getResponse().getContentAsString());
        String sessionId = login.getResponse().getHeader("Set-Cookie")
                .split(";")[0].substring("SESSION=".length());
        String accessToken = body.get("accessToken").asText();

        Thread.sleep(1200); // 等待两类凭据真实过期

        MvcResult viaSession = mvc.perform(get("/api/user/profile")
                        .cookie(new Cookie("SESSION", sessionId)))
                .andExpect(status().isUnauthorized()).andReturn();
        MvcResult viaToken = mvc.perform(get("/api/user/profile")
                        .header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isUnauthorized()).andReturn();
        log.info("input: expired session -> {}; expired token -> {}",
                viaSession.getResponse().getContentAsString(),
                viaToken.getResponse().getContentAsString());
        assertTrue(viaSession.getResponse().getContentAsString().contains("CREDENTIAL_EXPIRED"),
                "过期会话必须判定为 CREDENTIAL_EXPIRED");
        assertTrue(viaToken.getResponse().getContentAsString().contains("CREDENTIAL_EXPIRED"),
                "过期令牌必须判定为 CREDENTIAL_EXPIRED");
        // 过期凭据不得因后续请求复活
        mvc.perform(get("/api/user/profile").cookie(new Cookie("SESSION", sessionId)))
                .andExpect(status().isUnauthorized());
    }
}
