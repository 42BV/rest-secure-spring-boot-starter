package nl._42.restsecure.autoconfigure.test;

import nl._42.restsecure.autoconfigure.HttpSecurityCustomizer;
import nl._42.restsecure.autoconfigure.WebSecurityCustomizer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class CustomWebSecurityAndHttpSecurityConfig {

    private final Logger log = LoggerFactory.getLogger(getClass());
    
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
