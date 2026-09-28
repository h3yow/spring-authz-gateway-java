package com.github.h3yow.springauthzgatewayjava.web;

import com.github.h3yow.springauthzgatewayjava.auth.SessionRecord;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

/**
 * 会话 Cookie 的构造与清除。
 *
 * <p>关键语义：{@code Max-Age} 始终按"当前服务端失效时间 - 当前时刻"计算。
 * 登录时它等于完整空闲 TTL；滑动续期后过滤器用新失效时间重新下发同名 Cookie，
 * 浏览器保存的登录态随之与服务端一致地延长。到达空闲超时或绝对上限时，
 * 服务端判定失效并用 {@link #clear()} 立即清除浏览器 Cookie，两端同时结束。
 */
public final class SessionCookies {

    private SessionCookies() {}

    /** 下发/续期会话 Cookie：Max-Age 与记录当前的失效时间严格对齐（下限 0）。 */
    public static String issue(SessionRecord session) {
        return issue(session, Clock.systemUTC().instant());
    }

    static String issue(SessionRecord session, Instant now) {
        long maxAge = Math.max(0, Duration.between(now, session.expiresAt()).getSeconds());
        return AuthFilter.SESSION_COOKIE + "=" + session.sessionId()
                + "; Path=/; HttpOnly; SameSite=Strict; Max-Age=" + maxAge;
    }

    /** 服务端判定会话结束（过期/撤销）时立即清除浏览器侧登录态。 */
    public static String clear() {
        return AuthFilter.SESSION_COOKIE + "=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0";
    }
}
