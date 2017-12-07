package nl._42.restsecure.autoconfigure.shared.test;

import static org.springframework.boot.test.util.EnvironmentTestUtils.addEnvironment;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.anonymous;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.setup.MockMvcBuilders.webAppContextSetup;

import java.util.Set;

import nl._42.restsecure.autoconfigure.WebSecurityAutoConfig;
import nl._42.restsecure.autoconfigure.components.AuthenticationResult;
import nl._42.restsecure.autoconfigure.components.AuthenticationResultProvider;
import nl._42.restsecure.autoconfigure.userdetails.AbstractUserDetailsService;
import nl._42.restsecure.autoconfigure.userdetails.RegisteredUser;
import nl._42.restsecure.autoconfigure.userdetails.UserDetailsAdapter;

import org.junit.After;
import org.springframework.boot.autoconfigure.jackson.JacksonAutoConfiguration;
import org.springframework.boot.autoconfigure.web.HttpMessageConvertersAutoConfiguration;
import org.springframework.boot.autoconfigure.web.WebMvcAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;

import com.google.common.collect.Sets;

public class AbstractApplicationContextTest {

    protected AnnotationConfigWebApplicationContext context;
    
    @After
    public void tearDown() {
        if (this.context != null) {
            this.context.close();
        }
    }
    
    protected MockMvc getWebClient() {
        return getWebClient((Class<?>)null);
    }

    protected MockMvc getWebClient(RegisteredUser user) {
        return getWebClient(null, user);
    }

    protected MockMvc getWebClient(Class<?> appConfig) {
        return getWebClient(appConfig, null);
    }
    
    protected MockMvc getWebClient(Class<?> appConfig, RegisteredUser user) {
        loadApplicationContext(appConfig != null ? appConfig : ConfigWithNoopPasswordEncoder.class);
        return webAppContextSetup(context)
            .apply(springSecurity())
            .defaultRequest(get("/")
                .contentType(APPLICATION_JSON)
                .with(csrf())
                .with(user != null ? user(new UserDetailsAdapter<RegisteredUser>(user)) : anonymous()))
            .alwaysDo(print())
            .build();
    }
    
    @Configuration    
    protected static class ConfigWithUserDetailsService {
        @Bean
        public AbstractUserDetailsService<CustomUser> userDetailsService() {
            return new AbstractUserDetailsService<CustomUser>() {                
                @Override
                public CustomUser findUserByUsername(String username) {
                    return new CustomUser();
                }
            };
        }
    }
        
    protected static class ConfigWithNoopPasswordEncoder extends ConfigWithUserDetailsService {
        @Bean
        public PasswordEncoder passwordEncoder() {
            return NoOpPasswordEncoder.getInstance();
        }
    }
    
    protected static class ConfigWithCustomAuthenticationResultProvider extends ConfigWithNoopPasswordEncoder {
        @Bean
        public AuthenticationResultProvider<RegisteredUser> authenticationResultProvider() {
            return new AuthenticationResultProvider<RegisteredUser>() {
                @Override
                public AuthenticationResult toAuthenticationResult(RegisteredUser user) {
                    return new AuthenticationResult() {                        
                        @Override
                        public String getUsername() {
                            return "customized";
                        }
                        @Override
                        public Set<String> getAuthorities() {
                            return user.getAuthorities();
                        }
                    };
                }                
            };
        }
    }
    
    public static class CustomUser implements RegisteredUser {

        @Override
        public String getUsername() {
            return "username";
        }

        @Override
        public String getPassword() {
            return "password";
        }

        @Override
        public Set<String> getAuthorities() {
            return Sets.newHashSet("ROLE_ADMIN");
        }
        
        public boolean accountNonExpired() {
            return false;
        }
    }
    
    protected void loadApplicationContext(String... env) {
        loadApplicationContext(null, env);
    }

    protected void loadApplicationContext(Class<?> config, String... env) {
        AnnotationConfigWebApplicationContext applicationContext = new AnnotationConfigWebApplicationContext();
        addEnvironment(applicationContext, env);
        if (config != null) {
            applicationContext.register(config);
        }
        applicationContext.register(
                WebMvcAutoConfiguration.class,
                JacksonAutoConfiguration.class,
                HttpMessageConvertersAutoConfiguration.class,
                WebSecurityAutoConfig.class);
        applicationContext.setServletContext(new MockServletContext());
        applicationContext.refresh();
        this.context = applicationContext;
    }
}
