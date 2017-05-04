package nl._42.restsecure.autoconfigure;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;

public interface HttpSecurityCustomizer {

    HttpSecurity customize(HttpSecurity http) throws Exception;
}
