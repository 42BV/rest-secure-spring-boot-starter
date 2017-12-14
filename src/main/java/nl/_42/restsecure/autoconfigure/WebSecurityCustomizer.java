package nl._42.restsecure.autoconfigure;

import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.WebSecurity;

/**
 * Implement this interface and add it as a {@link Bean} to the {@link ApplicationContext} to be able to configure {@link WebSecurity}. 
 * For example, if you wish to ignore certain requests.
 */
public interface WebSecurityCustomizer {

    void configure(WebSecurity web) throws Exception;

}
