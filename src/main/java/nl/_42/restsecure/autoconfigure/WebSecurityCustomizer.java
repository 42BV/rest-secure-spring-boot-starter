package nl._42.restsecure.autoconfigure;

import org.springframework.security.config.annotation.web.builders.WebSecurity;

public interface WebSecurityCustomizer {

    void configure(WebSecurity web) throws Exception;

}
