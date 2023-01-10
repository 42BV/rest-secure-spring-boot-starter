package nl._42.restsecure.autoconfigure.test;

import lombok.extern.slf4j.Slf4j;
import nl._42.restsecure.autoconfigure.HttpSecurityCustomizer;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;

@Slf4j
@Configuration
public class CustomWebSecurityAndHttpSecurityConfig {

    @Bean
    public WebSecurityCustomizer WebSecurityCustomizer() {
        return web -> log.info("WebSecurityCustomizer called!");
    }

    @Bean
    public HttpSecurityCustomizer httpSecurityCustomizer() {
        return http -> {
            log.info("HttpSecurityCustomizer called!");
            return http;
        };
    }
}
