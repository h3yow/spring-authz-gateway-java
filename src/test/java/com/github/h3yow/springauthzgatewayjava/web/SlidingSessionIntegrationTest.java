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
 * 滑动续期的客户端侧行为端到端验证（真实等待的短 TTL 配置）：
 * <ul>
 *   <li>持续活跃时，每次响应重写 SESSION Cookie 的 Max-Age 并同步 X-Session-Expires-At，
 *       客户端登录态随服务端一致延长，不会在"最初登录算出的过期点"被踢下线；</li>
 *   <li>空闲超过 TTL 后服务端 401(CREDENTIAL_EXPIRED) 且响应清除旧 Cookie，两侧一致结束；</li>
 *   <li>绝对上限到达后同样一致结束。</li>
 * </ul>
 */
@SpringBootTest(properties = {
        "auth.session-ttl=3s",
        "auth.session-max-lifetime=8s",
        "auth.access-token-ttl=3s"
})
@AutoConfigureMockMvc
class SlidingSessionIntegrationTest {

    private static final Logger log = LoggerFactory.getLogger(SlidingSessionIntegrationTest.class);

    @Autowired
    private MockMvc mvc;
    private final ObjectMapper om = new ObjectMapper();

    private String loginSession() throws Exception {
        MvcResult login = mvc.perform(post("/api/auth/login")
                        .header("X-Forwarded-For", "10.50.0.1")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"alice\",\"password\":\"alice-pass-123\"}"))
                .andExpect(status().isOk()).andReturn();
        return login.getResponse().getHeader("Set-Cookie")
                .split(";")[0].substring("SESSION=".length());
    }

    private MvcResult useSession(String sessionId) throws Exception {
        return mvc.perform(get("/api/user/profile").cookie(new Cookie("SESSION", sessionId)))
                .andReturn();
    }

    private static long maxAge(String setCookie) {
        for (String part : setCookie.split(";")) {
            String t = part.trim();
            if (t.startsWith("Max-Age=")) {
                return Long.parseLong(t.substring("Max-Age=".length()));
            }
        }
        throw new IllegalStateException("no Max-Age in " + setCookie);
    }

    @Test
    void continuousActivityKeepsClientCookieAlivePastInitialExpiry() throws Exception {
        String sessionId = loginSession();
        // 初始过期点在登录后 3s；每隔 1s 活跃一次，跨越初始过期点仍保持登录
        String lastExpiresAt = null;
        long lastMaxAge = -1;
        for (int i = 0; i < 6; i++) {
            Thread.sleep(1000);
            MvcResult r = useSession(sessionId);
            assertEquals(200, r.getResponse().getStatus(), "持续活跃期间不得在初始过期点被踢下线");
            String setCookie = r.getResponse().getHeader("Set-Cookie");
            String expiresAt = r.getResponse().getHeader("X-Session-Expires-At");
            String renewed = r.getResponse().getHeader("X-Session-Renewed");
            assertNotNull(setCookie, "每次会话响应必须重写 SESSION Cookie");
            assertNotNull(expiresAt, "X-Session-Expires-At 必须可读");
            assertNotNull(renewed, "X-Session-Renewed 必须可读");
            assertTrue(setCookie.startsWith("SESSION=" + sessionId), "重写的 Cookie 必须沿用同一会话标识");
            long age = maxAge(setCookie);
            log.info("active t={}s -> status=200 renewed={} expiresAt={} cookieMaxAge={}s",
                    i + 1, renewed, expiresAt, age);
            if (lastExpiresAt != null && Boolean.parseBoolean(renewed)) {
                assertTrue(expiresAt.compareTo(lastExpiresAt) > 0, "续期时失效时间必须向后推");
            }
            lastExpiresAt = expiresAt;
            lastMaxAge = age;
        }
        assertTrue(lastMaxAge >= 1, "最后一次响应的 Cookie 仍应有剩余寿命");
    }

    @Test
    void idleTimeoutEndsSessionOnBothSides() throws Exception {
        String sessionId = loginSession();
        Thread.sleep(3600); // 超过空闲 TTL（3s）且无活动
        MvcResult r = useSession(sessionId);
        log.info("idle timeout -> status={} body={} setCookie={}",
                r.getResponse().getStatus(), r.getResponse().getContentAsString(),
                r.getResponse().getHeaders("Set-Cookie"));
        assertEquals(401, r.getResponse().getStatus());
        assertTrue(r.getResponse().getContentAsString().contains("CREDENTIAL_EXPIRED"),
                "空闲超时必须稳定判定为 CREDENTIAL_EXPIRED");
        String clearCookie = r.getResponse().getHeaders("Set-Cookie").stream()
                .filter(c -> c.startsWith("SESSION=") && c.contains("Max-Age=0"))
                .findFirst().orElse(null);
        assertNotNull(clearCookie, "服务端判定过期时必须同步清除客户端 Cookie");
        // 再次请求：拒绝原因不漂移，Cookie 仍被要求清除
        MvcResult again = useSession(sessionId);
        assertEquals(401, again.getResponse().getStatus());
        assertTrue(again.getResponse().getContentAsString().contains("CREDENTIAL_EXPIRED"),
                "同一过期凭据重复请求拒绝原因不得漂移为撤销/无效");
    }

    @Test
    void absoluteMaxLifetimeEndsSessionEvenWhenActive() throws Exception {
        String sessionId = loginSession();
        // 每 1s 活跃：空闲永不超时，但绝对上限 8s 必到
        MvcResult last = null;
        for (int i = 0; i < 7; i++) {
            Thread.sleep(1000);
            last = useSession(sessionId);
            if (last.getResponse().getStatus() != 200) {
                break;
            }
        }
        Thread.sleep(1600); // 越过 8s 绝对上限
        MvcResult r = useSession(sessionId);
        log.info("after absolute max lifetime -> status={} body={}",
                r.getResponse().getStatus(), r.getResponse().getContentAsString());
        assertEquals(401, r.getResponse().getStatus(), "到达绝对上限后服务端必须结束会话");
        assertTrue(r.getResponse().getContentAsString().contains("CREDENTIAL_EXPIRED"));
        assertNotNull(r.getResponse().getHeaders("Set-Cookie").stream()
                .filter(c -> c.contains("Max-Age=0")).findFirst().orElse(null),
                "到达绝对上限时也必须清除客户端 Cookie");
    }

    @Test
    void expiredSessionCookieIsClearedWhileBearerStillWorks() throws Exception {
        MvcResult login = mvc.perform(post("/api/auth/login")
                        .header("X-Forwarded-For", "10.50.0.2")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"alice\",\"password\":\"alice-pass-123\"}"))
                .andExpect(status().isOk()).andReturn();
        String sessionId = login.getResponse().getHeader("Set-Cookie")
                .split(";")[0].substring("SESSION=".length());
        String accessToken = om.readTree(login.getResponse().getContentAsString())
                .get("accessToken").asText();
        Thread.sleep(3600); // 会话与访问令牌均过期——先重新登录拿一个新 Bearer
        MvcResult reLogin = mvc.perform(post("/api/auth/login")
                        .header("X-Forwarded-For", "10.50.0.3")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"alice\",\"password\":\"alice-pass-123\"}"))
                .andExpect(status().isOk()).andReturn();
        String freshBearer = om.readTree(reLogin.getResponse().getContentAsString())
                .get("accessToken").asText();
        // 旧（过期）会话 Cookie + 新的有效 Bearer：请求成功，且响应顺带清除旧 Cookie
        MvcResult r = mvc.perform(get("/api/user/profile")
                        .cookie(new Cookie("SESSION", sessionId))
                        .header("Authorization", "Bearer " + freshBearer))
                .andExpect(status().isOk()).andReturn();
        assertNotNull(r.getResponse().getHeaders("Set-Cookie").stream()
                .filter(c -> c.startsWith("SESSION=") && c.contains("Max-Age=0"))
                .findFirst().orElse(null), "失效旧会话 Cookie 必须在 Bearer 成功时被清除");
        log.info("stale session cookie cleared while fresh bearer succeeded; old token len={}",
                accessToken.length());
    }
}
