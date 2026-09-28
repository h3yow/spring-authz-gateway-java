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
 *
 * <p>回归要点：同一个过期凭据重复访问时原因不得漂移——修复前第二次请求会变成
 * CREDENTIAL_REVOKED（过期记录在首次判定时被惰性删除）。
 */
@SpringBootTest(properties = {
        "auth.session-ttl=1s",
        "auth.access-token-ttl=1s",
        "auth.revocation-retention=1h"
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

    @Test
    void expiredReasonDoesNotDriftAcrossRepeatedRequestsAndEntryPoints() throws Exception {
        MvcResult login = mvc.perform(post("/api/auth/login")
                        .header("X-Forwarded-For", "10.40.0.11")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"alice\",\"password\":\"alice-pass-123\"}"))
                .andExpect(status().isOk()).andReturn();
        String sessionId = login.getResponse().getHeader("Set-Cookie")
                .split(";")[0].substring("SESSION=".length());
        JsonNode body = om.readTree(login.getResponse().getContentAsString());
        String accessToken = body.get("accessToken").asText();
        String refreshToken = body.get("refreshToken").asText();

        Thread.sleep(1200);

        // 同一过期会话连续 3 次、且换不同受保护入口：原因始终 CREDENTIAL_EXPIRED
        for (int i = 0; i < 3; i++) {
            MvcResult r = mvc.perform(get(i % 2 == 0 ? "/api/user/profile" : "/api/auth/credentials")
                            .cookie(new Cookie("SESSION", sessionId)))
                    .andExpect(status().isUnauthorized()).andReturn();
            String b = r.getResponse().getContentAsString();
            assertTrue(b.contains("CREDENTIAL_EXPIRED"), "过期会话第 " + (i + 1) + " 次请求不得漂移: " + b);
            assertFalse(b.contains("CREDENTIAL_REVOKED"));
            assertFalse(b.contains(sessionId), "响应不得包含会话标识原文");
        }
        // 同一过期访问令牌连续 3 次：原因始终 CREDENTIAL_EXPIRED
        for (int i = 0; i < 3; i++) {
            String b = mvc.perform(get("/api/user/profile")
                            .header("Authorization", "Bearer " + accessToken))
                    .andExpect(status().isUnauthorized()).andReturn()
                    .getResponse().getContentAsString();
            assertTrue(b.contains("CREDENTIAL_EXPIRED"), "过期令牌第 " + (i + 1) + " 次请求不得漂移: " + b);
            assertFalse(b.contains("CREDENTIAL_REVOKED"));
            assertFalse(b.contains(accessToken), "响应不得包含令牌原文");
        }
        log.info("decision: same expired credential stays CREDENTIAL_EXPIRED across repeated requests/entries");
    }

    @Test
    void consumedRefreshTokenIsStableAndMissingBodyIsNoCredentials() throws Exception {
        // 已用刷新令牌稳定 CREDENTIAL_REVOKED：先正常刷新消费，再重复提交
        MvcResult fresh = mvc.perform(post("/api/auth/login")
                        .header("X-Forwarded-For", "10.40.0.13")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"alice\",\"password\":\"alice-pass-123\"}"))
                .andExpect(status().isOk()).andReturn();
        String usableRefresh = om.readTree(fresh.getResponse().getContentAsString()).get("refreshToken").asText();
        mvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + usableRefresh + "\"}"))
                .andExpect(status().isOk());
        for (int i = 0; i < 3; i++) {
            String b = mvc.perform(post("/api/auth/refresh")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"refreshToken\":\"" + usableRefresh + "\"}"))
                    .andExpect(status().isUnauthorized()).andReturn()
                    .getResponse().getContentAsString();
            assertTrue(b.contains("CREDENTIAL_REVOKED"), "已用刷新令牌重复提交必须稳定为已撤销: " + b);
            assertFalse(b.contains("CREDENTIAL_EXPIRED"));
        }
        // 无刷新令牌体 -> NO_CREDENTIALS
        String none = mvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isUnauthorized()).andReturn().getResponse().getContentAsString();
        assertTrue(none.contains("NO_CREDENTIALS"));
        log.info("decision: consumed refresh token stays CREDENTIAL_REVOKED; empty body is NO_CREDENTIALS");
    }
}
