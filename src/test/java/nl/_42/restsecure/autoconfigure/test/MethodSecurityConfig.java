package nl._42.restsecure.autoconfigure.test;

import nl._42.restsecure.autoconfigure.authentication.InMemoryUserDetailService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class MethodSecurityConfig {

  @Bean
  public InMemoryUserDetailService userDetailService() {
    return new InMemoryUserDetailService();
  }

  @Bean
  public SecuredService securedService() {
    return new SecuredService();
  }

}
