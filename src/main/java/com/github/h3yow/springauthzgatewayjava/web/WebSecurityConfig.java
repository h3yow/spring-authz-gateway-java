package com.github.h3yow.springauthzgatewayjava.web;

import com.github.h3yow.springauthzgatewayjava.auth.AuthProperties;
import com.github.h3yow.springauthzgatewayjava.auth.SessionService;
import com.github.h3yow.springauthzgatewayjava.auth.TokenService;
import com.github.h3yow.springauthzgatewayjava.authz.AccessPolicy;
import java.util.List;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

/**
 * 过滤器链装配与 CORS 配置。
 *
 * <p>顺序：CORS（0） -> 认证/授权（1） -> CSRF（2）。
 * CORS 仅放行 {@code auth.allowed-origins} 中显式声明的来源，未声明来源不放行；
 * 预检请求由 CorsFilter 直接应答，不进入认证过滤器，避免被误伤。
 */
@Configuration
@EnableConfigurationProperties(AuthProperties.class)
public class WebSecurityConfig {

    @Bean
    public FilterRegistrationBean<CorsFilter> corsFilterRegistration(AuthProperties properties) {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(properties.getAllowedOrigins()); // 精确来源，不使用通配
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));
        config.setAllowedHeaders(List.of("Authorization", "Content-Type", CsrfFilter.CSRF_HEADER));
        config.setExposedHeaders(List.of(
                CsrfFilter.CSRF_HEADER,
                AuthFilter.CORRELATION_HEADER,
                AuthFilter.SESSION_EXPIRES_AT_HEADER,
                AuthFilter.SESSION_RENEWED_HEADER));
        config.setAllowCredentials(true);
        config.setMaxAge(3600L);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        FilterRegistrationBean<CorsFilter> bean = new FilterRegistrationBean<>(new CorsFilter(source));
        bean.setOrder(0);
        return bean;
    }

    @Bean
    public FilterRegistrationBean<AuthFilter> authFilterRegistration(
            SessionService sessionService, TokenService tokenService, AccessPolicy accessPolicy) {
        FilterRegistrationBean<AuthFilter> bean = new FilterRegistrationBean<>(
                new AuthFilter(sessionService, tokenService, accessPolicy));
        bean.setOrder(1);
        return bean;
    }

    @Bean
    public FilterRegistrationBean<CsrfFilter> csrfFilterRegistration(SessionService sessionService) {
        FilterRegistrationBean<CsrfFilter> bean = new FilterRegistrationBean<>(new CsrfFilter(sessionService));
        bean.setOrder(2);
        return bean;
    }
}
