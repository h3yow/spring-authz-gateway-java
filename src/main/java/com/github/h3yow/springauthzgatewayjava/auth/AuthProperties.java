package com.github.h3yow.springauthzgatewayjava.auth;

import java.time.Duration;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;

/** 安全相关可配置项：限流阈值/窗口/锁定时长、会话与令牌有效期、会话绝对最长存活时间、CORS 允许来源。 */
@ConfigurationProperties(prefix = "auth")
public class AuthProperties {

    private int loginMaxFailures = 5;
    private Duration loginFailureWindow = Duration.ofMinutes(5);
    private Duration lockoutDuration = Duration.ofMinutes(10);
    private Duration sessionTtl = Duration.ofMinutes(30);
    private Duration sessionMaxLifetime = Duration.ofHours(12);
    private Duration accessTokenTtl = Duration.ofMinutes(10);
    private Duration refreshTokenTtl = Duration.ofHours(12);
    /** 拒绝原因稳定期：撤销/过期墓碑在此期间保留，使同一凭据的拒绝原因不随重复请求漂移。 */
    private Duration revocationRetention = Duration.ofHours(24);
    private List<String> allowedOrigins = List.of();

    public int getLoginMaxFailures() { return loginMaxFailures; }
    public void setLoginMaxFailures(int v) { this.loginMaxFailures = v; }
    public Duration getLoginFailureWindow() { return loginFailureWindow; }
    public void setLoginFailureWindow(Duration v) { this.loginFailureWindow = v; }
    public Duration getLockoutDuration() { return lockoutDuration; }
    public void setLockoutDuration(Duration v) { this.lockoutDuration = v; }
    public Duration getSessionTtl() { return sessionTtl; }
    public void setSessionTtl(Duration v) { this.sessionTtl = v; }
    public Duration getSessionMaxLifetime() { return sessionMaxLifetime; }
    public void setSessionMaxLifetime(Duration v) { this.sessionMaxLifetime = v; }
    public Duration getAccessTokenTtl() { return accessTokenTtl; }
    public void setAccessTokenTtl(Duration v) { this.accessTokenTtl = v; }
    public Duration getRefreshTokenTtl() { return refreshTokenTtl; }
    public void setRefreshTokenTtl(Duration v) { this.refreshTokenTtl = v; }
    public Duration getRevocationRetention() { return revocationRetention; }
    public void setRevocationRetention(Duration v) { this.revocationRetention = v; }
    public List<String> getAllowedOrigins() { return allowedOrigins; }
    public void setAllowedOrigins(List<String> v) { this.allowedOrigins = v; }
}
