package nl._42.restsecure.autoconfigure;

import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;

/**
 * Implement this interface and add it as {@link Bean} to the {@link ApplicationContext} to customize the auto configured url registry.
 * Your matched urls will be put between the already publicly configured /authentication urls and fully restricted any other request urls.   
 */
public interface RequestAuthorizationCustomizer {

    ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry customize(ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry urlRegistry) throws Exception;
}
