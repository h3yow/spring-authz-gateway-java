package com.github.h3yow.springauthzgatewayjava.config;

import java.time.Clock;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * 提供可替换的时钟，测试中可注入可变 Clock 以验证窗口与锁定到期。
 */
@Configuration
public class ClockConfig {

    @Bean
    public Clock systemClock() {
        return Clock.systemUTC();
    }
}
