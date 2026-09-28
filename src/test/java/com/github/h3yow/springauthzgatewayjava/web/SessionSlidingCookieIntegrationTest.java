package com.github.h3yow.springauthzgatewayjava.web;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import jakarta.servlet.http.Cookie;
import java.time.Duration;
import java.time.Instant;
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
 * 滑动续期在客户端侧的实际行为：
 * <ul>
 *   <li>持续活跃时，每次响应重新下发的 SESSION Cookie 的 Max-Age 都与服务端
 *       {@code X-Session-Expires-At} 对齐地延长——浏览器登录态不会停在最初的过期点；</li>
 *   <li>续期是否发生（X-Session-Renewed）与新的失效时间（X-Session-Expires-At）
 *       在每次响应中都可稳定读取（含跨域暴露，见 CORS 配置与 SecurityIntegrationTest）；</li>
 *   <li>到达绝对上限后，服务端判定失效并清除浏览器 Cookie，两端一致结束。</li>
 * </ul>
 * 使用秒级超短 TTL 与绝对上限构造真实边界。
 */
@SpringBootTest(properties = {
        "auth.session-ttl=2s",
        "auth.session-max-lifetime=6s",
        "auth.access-token-ttl=2s"
})
@AutoConfigureMockMvc
class SessionSlidingCookieIntegrationTest {

    private static final Logger log = LoggerFactory.getLogger(SessionSlidingCookieIntegrationTest.class);

    @Autowired
    private MockMvc mvc;

    private record SetCookieInfo(String value, long maxAge) {}

    private String login(String ip) throws Exception {
        MvcResult r = mvc.perform(post("/api/auth/login")
                        .header("X-Forwarded-For", ip)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"alice\",\"password\":\"alice-pass-123\"}"))
                .andExpect(status().isOk()).andReturn();
        String sc = r.getResponse().getHeader("Set-Cookie");
        assertNotNull(r.getResponse().getHeader(AuthFilter.SESSION_EXPIRES_AT_HEADER));
        return sc.split(";")[0].substring("SESSION=".length());
    }

    private static SetCookieInfo parseSessionCookie(MvcResult r) {
        // 每个会话响应恰好重发一个 SESSION Cookie
        String setCookie = r.getResponse().getHeader("Set-Cookie");
        assertNotNull(setCookie, "会话响应必须重发 Set-Cookie 以滑动客户端存活时间");
        long maxAge = -1;
        for (String part : setCookie.split(";")) {
            String t = part.trim();
            if (t.startsWith("Max-Age=")) {
                maxAge = Long.parseLong(t.substring("Max-Age=".length()));
            }
        }
        return new SetCookieInfo(setCookie.split(";")[0].substring("SESSION=".length()), maxAge);
    }

    @Test
    void cookieMaxAgeSlidesWithServerExpiryWhileActive() throws Exception {
        String sessionId = login("10.50.0.1");

        // 第 1 秒：保持活跃（不足 TTL 一半=1s? 此处 ttl=2s，半阈值=1s；1s 后访问应续期）
        MvcResult first = mvc.perform(get("/api/user/profile").cookie(new Cookie("SESSION", sessionId)))
                .andExpect(status().isOk()).andReturn();
        SetCookieInfo c1 = parseSessionCookie(first);
        assertEquals(sessionId, c1.value(), "滑动续期不得更换会话标识");
        Instant expires1 = Instant.parse(first.getResponse().getHeader(AuthFilter.SESSION_EXPIRES_AT_HEADER));
        log.info("input: active request #1 -> renewed={} expiresAt={} cookieMaxAge={}s",
                first.getResponse().getHeader(AuthFilter.SESSION_RENEWED_HEADER), expires1, c1.maxAge());

        Thread.sleep(1100); // 在空闲超时（2s）内再次活跃
        MvcResult second = mvc.perform(get("/api/user/profile").cookie(new Cookie("SESSION", sessionId)))
                .andExpect(status().isOk()).andReturn();
        SetCookieInfo c2 = parseSessionCookie(second);
        Instant expires2 = Instant.parse(second.getResponse().getHeader(AuthFilter.SESSION_EXPIRES_AT_HEADER));
        log.info("input: active request #2 -> renewed={} expiresAt={} cookieMaxAge={}s",
                second.getResponse().getHeader(AuthFilter.SESSION_RENEWED_HEADER), expires2, c2.maxAge());

        assertEquals("true", second.getResponse().getHeader(AuthFilter.SESSION_RENEWED_HEADER),
                "剩余不足一半时服务端必须续期");
        assertTrue(expires2.isAfter(expires1), "服务端失效时间必须后移");
        // 客户端 Cookie 的 Max-Age 与新失效时间对齐（允许 1s 取整误差）
        long secondsToExpiry = Duration.between(Instant.now(), expires2).getSeconds();
        assertTrue(Math.abs(c2.maxAge() - secondsToExpiry) <= 1,
                "客户端 Cookie Max-Age 必须与服务端失效时间一致滑动，candidate=" + c2.maxAge()
                        + " server=" + secondsToExpiry);
        assertTrue(c2.maxAge() >= 1, "持续活跃时客户端登录态不得停在最初的过期点");
    }

    @Test
    void renewalHeadersAreVisibleCrossOrigin() throws Exception {
        String sessionId = login("10.50.0.9");
        MvcResult r = mvc.perform(get("/api/user/profile")
                        .header("Origin", "http://localhost:3000")
                        .cookie(new Cookie("SESSION", sessionId)))
                .andExpect(status().isOk()).andReturn();
        assertEquals("http://localhost:3000", r.getResponse().getHeader("Access-Control-Allow-Origin"),
                "声明的跨域来源必须被放行");
        assertNotNull(r.getResponse().getHeader(AuthFilter.SESSION_EXPIRES_AT_HEADER));
        assertNotNull(r.getResponse().getHeader(AuthFilter.SESSION_ABSOLUTE_EXPIRES_AT_HEADER));
        assertNotNull(r.getResponse().getHeader(AuthFilter.SESSION_RENEWED_HEADER));
        assertNotNull(r.getResponse().getHeader("Set-Cookie"),
                "跨域续期响应也必须重发滑动后的会话 Cookie");
        log.info("input: cross-origin session request -> expose/renewal headers and Set-Cookie present");
    }

    @Test
    void idleTimeoutEndsSessionOnBothSidesConsistently() throws Exception {
        String sessionId = login("10.50.0.2");
        Thread.sleep(2300); // 超过空闲 TTL（2s）
        MvcResult r = mvc.perform(get("/api/user/profile").cookie(new Cookie("SESSION", sessionId)))
                .andExpect(status().isUnauthorized()).andReturn();
        String body = r.getResponse().getContentAsString();
        log.info("input: idle beyond ttl -> {} Set-Cookie={}", body, r.getResponse().getHeader("Set-Cookie"));
        assertTrue(body.contains("CREDENTIAL_EXPIRED"), "空闲超时必须稳定判定为过期");
        String setCookie = r.getResponse().getHeader("Set-Cookie");
        assertNotNull(setCookie, "服务端判定过期时必须同步清除浏览器 Cookie");
        assertTrue(setCookie.contains("Max-Age=0"), "必须下发清除 Cookie，两端一致结束");
        // 重复请求原因不漂移
        mvc.perform(get("/api/user/profile").cookie(new Cookie("SESSION", sessionId)))
                .andExpect(status().isUnauthorized())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("CREDENTIAL_EXPIRED")));
    }

    @Test
    void absoluteCapEndsSessionEvenWhenContinuouslyActive() throws Exception {
        String sessionId = login("10.50.0.3");
        // 每 1s 活跃一次（< 空闲 ttl 2s），持续越过绝对上限 6s
        for (int i = 0; i < 6; i++) {
            Thread.sleep(1000);
            MvcResult r = mvc.perform(get("/api/user/profile").cookie(new Cookie("SESSION", sessionId)))
                    .andReturn();
            log.info("input: active tick {} -> status={}", i + 1, r.getResponse().getStatus());
            if (r.getResponse().getStatus() != 200) {
                // 已到绝对上限：必须是过期，且清除 Cookie
                String body = r.getResponse().getContentAsString();
                assertTrue(body.contains("CREDENTIAL_EXPIRED"), "到达绝对上限必须判定过期");
                String sc = r.getResponse().getHeader("Set-Cookie");
                assertNotNull(sc);
                assertTrue(sc.contains("Max-Age=0"), "绝对上限到达时必须同步清除客户端 Cookie");
                // 再请求一次：原因稳定，Cookie 仍被要求清除
                MvcResult again = mvc.perform(get("/api/user/profile")
                                .cookie(new Cookie("SESSION", sessionId)))
                        .andExpect(status().isUnauthorized()).andReturn();
                assertTrue(again.getResponse().getContentAsString().contains("CREDENTIAL_EXPIRED"));
                return;
            }
        }
        // 若循环内最后一次恰好为 200，则再活跃一次必越上限（总时长 >= 7s > 6s）
        MvcResult beyond = mvc.perform(get("/api/user/profile").cookie(new Cookie("SESSION", sessionId)))
                .andExpect(status().isUnauthorized()).andReturn();
        assertTrue(beyond.getResponse().getContentAsString().contains("CREDENTIAL_EXPIRED"));
        assertTrue(beyond.getResponse().getHeader("Set-Cookie").contains("Max-Age=0"));
        log.info("decision: continuously active session ended at absolute cap, both sides aligned");
    }
}
