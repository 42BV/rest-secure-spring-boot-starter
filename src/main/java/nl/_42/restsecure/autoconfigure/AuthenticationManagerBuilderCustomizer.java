package nl._42.restsecure.autoconfigure;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;

public interface AuthenticationManagerBuilderCustomizer {

    AuthenticationManagerBuilder customize(AuthenticationManagerBuilder auth);
}
