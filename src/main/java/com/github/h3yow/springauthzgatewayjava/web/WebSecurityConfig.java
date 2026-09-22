package com.github.h3yow.springauthzgatewayjava.web;

import com.github.h3yow.springauthzgatewayjava.auth.UserStore;
import com.github.h3yow.springauthzgatewayjava.auth.session.SessionService;
import com.github.h3yow.springauthzgatewayjava.auth.token.TokenService;
import com.github.h3yow.springauthzgatewayjava.authz.AccessDecisionService;
import com.github.h3yow.springauthzgatewayjava.config.AuthSecurityProperties;
import java.util.List;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * 装配安全组件。过滤器顺序：
 * 关联标识 → CORS（合法预检直接放行，未声明来源不加 CORS 头）→ 认证解析 → CSRF。
 * 过滤器同时声明为 Bean（供 MockMvc 收集）与 FilterRegistrationBean（供容器排序）。
 */
@Configuration
public class WebSecurityConfig implements WebMvcConfigurer {

    private final AccessDecisionService accessDecisionService;

    public WebSecurityConfig(AccessDecisionService accessDecisionService) {
        this.accessDecisionService = accessDecisionService;
    }

    @Bean
    public CorrelationIdFilter correlationIdFilter() {
        return new CorrelationIdFilter();
    }

    @Bean
    public FilterRegistrationBean<CorrelationIdFilter> correlationIdFilterRegistration(CorrelationIdFilter filter) {
        FilterRegistrationBean<CorrelationIdFilter> bean = new FilterRegistrationBean<>(filter);
        bean.setOrder(1);
        return bean;
    }

    @Bean
    public CorsFilter corsFilter(AuthSecurityProperties props) {
        CorsConfiguration config = new CorsConfiguration();
        // 仅放行显式声明的来源；不使用通配符，未声明来源不会得到任何 CORS 许可头
        config.setAllowedOrigins(props.getAllowedOrigins());
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of("Authorization", "Content-Type", "X-CSRF-Token", "X-Correlation-Id"));
        config.setAllowCredentials(true);
        config.setMaxAge(3600L);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return new CorsFilter(source);
    }

    @Bean
    public FilterRegistrationBean<CorsFilter> corsFilterRegistration(CorsFilter filter) {
        FilterRegistrationBean<CorsFilter> bean = new FilterRegistrationBean<>(filter);
        bean.setOrder(2);
        return bean;
    }

    @Bean
    public AuthFilter authFilter(SessionService sessionService, TokenService tokenService, UserStore userStore) {
        return new AuthFilter(sessionService, tokenService, userStore);
    }

    @Bean
    public FilterRegistrationBean<AuthFilter> authFilterRegistration(AuthFilter filter) {
        FilterRegistrationBean<AuthFilter> bean = new FilterRegistrationBean<>(filter);
        bean.setOrder(3);
        return bean;
    }

    @Bean
    public CsrfFilter csrfFilter(SessionService sessionService, AuthSecurityProperties props) {
        return new CsrfFilter(sessionService, props);
    }

    @Bean
    public FilterRegistrationBean<CsrfFilter> csrfFilterRegistration(CsrfFilter filter) {
        FilterRegistrationBean<CsrfFilter> bean = new FilterRegistrationBean<>(filter);
        bean.setOrder(4);
        return bean;
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new AuthzInterceptor(accessDecisionService))
                .addPathPatterns("/api/**");
    }
}
