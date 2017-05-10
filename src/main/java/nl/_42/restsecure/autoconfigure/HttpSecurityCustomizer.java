package nl._42.restsecure.autoconfigure;

import org.springframework.context.ApplicationContext;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

/**
 * Implement this interface and add it to the {@link ApplicationContext} to be able to customize the {@link HttpSecurity} object.
 * Note: to add url authorization, you may want to make use of {@link RequestAuthorizationCustomizer} instead. 
 * This because of the already auto configured url authorizations will otherwise prevent your added urls from being detected.
 */
public interface HttpSecurityCustomizer {

    HttpSecurity customize(HttpSecurity http) throws Exception;
}
