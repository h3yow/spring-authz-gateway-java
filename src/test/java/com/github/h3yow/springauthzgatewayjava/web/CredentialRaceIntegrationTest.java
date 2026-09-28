package com.github.h3yow.springauthzgatewayjava.web;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.Cookie;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
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
 * HTTP 级竞争收敛：同一个活跃会话上"持续访问（触发滑动续期）"与"撤销"并发进行，
 * 撤销完成后该会话必须稳定地对所有入口失效，任何续期都不得使其复活；
 * 旧失效凭据与另一种有效凭据并存时，状态变更仍由有效凭据完成，不受旧凭据影响。
 */
@SpringBootTest
@AutoConfigureMockMvc
class CredentialRaceIntegrationTest {

    private static final Logger log = LoggerFactory.getLogger(CredentialRaceIntegrationTest.class);

    @Autowired
    private MockMvc mvc;
    private final ObjectMapper om = new ObjectMapper();

    private record Credentials(String sessionId, String csrf, String accessToken) {}

    private Credentials login(String ip, String ua) throws Exception {
        MvcResult r = mvc.perform(post("/api/auth/login")
                        .header("X-Forwarded-For", ip).header("User-Agent", ua)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"alice\",\"password\":\"alice-pass-123\"}"))
                .andExpect(status().isOk()).andReturn();
        JsonNode body = om.readTree(r.getResponse().getContentAsString());
        String sessionId = r.getResponse().getHeader("Set-Cookie").split(";")[0]
                .substring("SESSION=".length());
        return new Credentials(sessionId, r.getResponse().getHeader("X-CSRF-Token"),
                body.get("accessToken").asText());
    }

    @Test
    void renewalVsRevokeConvergesToRevokedAtHttpLayer() throws Exception {
        Credentials c = login("10.60.0.1", "race-agent");
        int threads = 16;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger okDuringRace = new AtomicInteger();
        AtomicInteger rejectedDuringRace = new AtomicInteger();

        // 多个线程用同一会话持续访问（每次都触发判定+续期）
        for (int i = 0; i < threads - 1; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    for (int j = 0; j < 20; j++) {
                        int status = mvc.perform(get("/api/user/profile")
                                        .cookie(new Cookie("SESSION", c.sessionId())))
                                .andReturn().getResponse().getStatus();
                        if (status == 200) {
                            okDuringRace.incrementAndGet();
                        } else {
                            rejectedDuringRace.incrementAndGet();
                        }
                    }
                } catch (Exception ignored) {
                    // MockMvc 不抛预期外异常；忽略中断
                }
            });
        }
        // 一个线程用有效 Bearer 撤销该会话凭据
        pool.submit(() -> {
            try {
                start.await();
                var list = om.readTree(mvc.perform(get("/api/auth/credentials")
                                .header("Authorization", "Bearer " + c.accessToken()))
                        .andReturn().getResponse().getContentAsString());
                String target = null;
                for (JsonNode v : list) {
                    if ("race-agent".equals(v.get("client").asText())
                            && "SESSION".equals(v.get("kind").asText())) {
                        target = v.get("credentialId").asText();
                    }
                }
                assertNotNull(target);
                mvc.perform(delete("/api/auth/credentials/" + target)
                        .header("Authorization", "Bearer " + c.accessToken())).andReturn();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));

        // 收敛断言：竞争结束后，同一会话连续多次必须稳定 401 CREDENTIAL_REVOKED
        for (int i = 0; i < 5; i++) {
            MvcResult r = mvc.perform(get("/api/user/profile")
                            .cookie(new Cookie("SESSION", c.sessionId())))
                    .andExpect(status().isUnauthorized()).andReturn();
            String b = r.getResponse().getContentAsString();
            assertTrue(b.contains("CREDENTIAL_REVOKED"), "撤销收敛后不得再出现 EXPIRED/有效: " + b);
        }
        log.info("input: renewal({} ok / {} rejected during race) + revoke -> stable CREDENTIAL_REVOKED",
                okDuringRace.get(), rejectedDuringRace.get());
    }

    @Test
    void staleRevokedSessionDoesNotDragStateChangeWithValidBearer() throws Exception {
        Credentials c = login("10.60.0.2", "race-stale-agent");
        // 通过 Bearer 撤销自己的会话
        var list = om.readTree(mvc.perform(get("/api/auth/credentials")
                        .header("Authorization", "Bearer " + c.accessToken()))
                .andReturn().getResponse().getContentAsString());
        String target = null;
        for (JsonNode v : list) {
            if ("race-stale-agent".equals(v.get("client").asText())
                    && "SESSION".equals(v.get("kind").asText())) {
                target = v.get("credentialId").asText();
            }
        }
        mvc.perform(delete("/api/auth/credentials/" + target)
                .header("Authorization", "Bearer " + c.accessToken()))
                .andExpect(status().isNoContent());

        // 旧失效会话 Cookie（甚至带一个错误 CSRF）+ 有效 Bearer 的状态变更：必须成功，
        // 且响应不应因为旧 Cookie 而要求 CSRF
        for (int i = 0; i < 3; i++) {
            mvc.perform(post("/api/user/profile")
                            .cookie(new Cookie("SESSION", c.sessionId()))
                            .header("Authorization", "Bearer " + c.accessToken())
                            .header("X-CSRF-Token", "stale-and-wrong"))
                    .andExpect(status().isOk());
        }
        // 单独使用旧会话则稳定 401 CREDENTIAL_REVOKED
        MvcResult alone = mvc.perform(get("/api/user/profile")
                        .cookie(new Cookie("SESSION", c.sessionId())))
                .andExpect(status().isUnauthorized()).andReturn();
        assertTrue(alone.getResponse().getContentAsString().contains("CREDENTIAL_REVOKED"));
        log.info("decision: stale revoked session never drags state changes authenticated by valid bearer");
    }
}
