package nl._42.restsecure.autoconfigure.shared.test.config;

import nl._42.restsecure.autoconfigure.HttpSecurityCustomizer;
import nl._42.restsecure.autoconfigure.WebSecurityCustomizer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;

@Configuration
public class CustomWebSecurityAndHttpSecurityConfig {

    final Logger log = LoggerFactory.getLogger(getClass());
    
    @Bean
    public WebSecurityCustomizer WebSecurityCustomizer() {
        return new WebSecurityCustomizer() {
            @Override
            public void configure(WebSecurity web) throws Exception {
                log.info("WebSecurityCustomizer called!");
            }
        };
    }
    
    @Bean
    public HttpSecurityCustomizer httpSecurityCustomizer() {
        return new HttpSecurityCustomizer() {
            @Override
            public HttpSecurity customize(HttpSecurity http) throws Exception {
                log.info("HttpSecurityCustomizer called!");
                return http;
            }
        };
    }
    
}
