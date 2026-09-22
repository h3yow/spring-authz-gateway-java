package com.github.h3yow.springauthzgatewayjava.config;

import java.time.Duration;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * 认证与授权子系统的可配置项。
 */
@ConfigurationProperties(prefix = "app.security")
public class AuthSecurityProperties {

    /** 会话有效期 */
    private Duration sessionTtl = Duration.ofMinutes(30);
    /** 访问令牌有效期 */
    private Duration accessTokenTtl = Duration.ofMinutes(10);
    /** 刷新令牌有效期 */
    private Duration refreshTokenTtl = Duration.ofHours(2);
    /** 允许的跨域来源（精确匹配，不允许通配与凭据共存） */
    private List<String> allowedOrigins = List.of();
    /** 登录失败限流：窗口内最大失败次数 */
    private int loginMaxFailures = 5;
    /** 登录失败统计窗口 */
    private Duration loginFailureWindow = Duration.ofMinutes(5);
    /** 触发锁定后的锁定时长 */
    private Duration loginLockDuration = Duration.ofMinutes(10);
    /** 是否启用 CSRF 防护（针对会话方式的改状态请求） */
    private boolean csrfEnabled = true;

    public Duration getSessionTtl() { return sessionTtl; }
    public void setSessionTtl(Duration sessionTtl) { this.sessionTtl = sessionTtl; }
    public Duration getAccessTokenTtl() { return accessTokenTtl; }
    public void setAccessTokenTtl(Duration accessTokenTtl) { this.accessTokenTtl = accessTokenTtl; }
    public Duration getRefreshTokenTtl() { return refreshTokenTtl; }
    public void setRefreshTokenTtl(Duration refreshTokenTtl) { this.refreshTokenTtl = refreshTokenTtl; }
    public List<String> getAllowedOrigins() { return allowedOrigins; }
    public void setAllowedOrigins(List<String> allowedOrigins) { this.allowedOrigins = allowedOrigins; }
    public int getLoginMaxFailures() { return loginMaxFailures; }
    public void setLoginMaxFailures(int loginMaxFailures) { this.loginMaxFailures = loginMaxFailures; }
    public Duration getLoginFailureWindow() { return loginFailureWindow; }
    public void setLoginFailureWindow(Duration loginFailureWindow) { this.loginFailureWindow = loginFailureWindow; }
    public Duration getLoginLockDuration() { return loginLockDuration; }
    public void setLoginLockDuration(Duration loginLockDuration) { this.loginLockDuration = loginLockDuration; }
    public boolean isCsrfEnabled() { return csrfEnabled; }
    public void setCsrfEnabled(boolean csrfEnabled) { this.csrfEnabled = csrfEnabled; }
}
