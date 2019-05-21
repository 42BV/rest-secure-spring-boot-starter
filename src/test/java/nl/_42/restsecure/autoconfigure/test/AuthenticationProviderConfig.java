package nl._42.restsecure.autoconfigure.test;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

@Configuration
public class AuthenticationProviderConfig {

  @Bean
  public AuthenticationProvider authenticationProvider() {
    return new AuthenticationProvider() {
      @Override
      public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        return authentication;
      }

      @Override
      public boolean supports(Class<?> authentication) {
        return true;
      }
    };
  }

}
