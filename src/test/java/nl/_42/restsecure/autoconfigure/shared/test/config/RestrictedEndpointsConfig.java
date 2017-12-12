package nl._42.restsecure.autoconfigure.shared.test.config;

import nl._42.restsecure.autoconfigure.RequestAuthorizationCustomizer;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;

@Configuration
public class RestrictedEndpointsConfig {

    @Bean
    public RequestAuthorizationCustomizer requestAuthorizationCustomizer() {
        return new RequestAuthorizationCustomizer() {
            @Override
            public ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry customize(
                    ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry urlRegistry) {
                return urlRegistry.antMatchers("/test/forbidden").hasRole("UNKNOWN");
            }
        };
    }
}
