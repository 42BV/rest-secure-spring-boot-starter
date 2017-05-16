package nl._42.restsecure.autoconfigure;

import static java.util.Arrays.asList;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.springframework.boot.test.util.EnvironmentTestUtils.addEnvironment;
import static org.springframework.test.util.ReflectionTestUtils.getField;

import java.util.List;

import org.junit.After;
import org.junit.Test;
import org.springframework.boot.autoconfigure.jackson.JacksonAutoConfiguration;
import org.springframework.boot.autoconfigure.web.HttpMessageConvertersAutoConfiguration;
import org.springframework.boot.autoconfigure.web.WebMvcAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;

import com.atlassian.crowd.integration.springsecurity.RemoteCrowdAuthenticationProvider;

import nl._42.restsecure.autoconfigure.components.errorhandling.WebMvcErrorHandler;
import nl._42.restsecure.autoconfigure.userdetails.AbstractUserDetailsService;
import nl._42.restsecure.autoconfigure.userdetails.RegisteredUser;

public class WebSecurityAutoConfigTest {

    private AnnotationConfigWebApplicationContext context;

    @After
    public void tearDown() {
        if (this.context != null) {
            this.context.close();
        }
    }
    
    @Test
    public void autoConfig_shouldConfigureSecurity_withDefaults() {
        loadApplicationContext(ConfigWithUserDetailsService.class);
        PasswordEncoder passwordEncoder = context.getBean(PasswordEncoder.class);
        assertEquals(BCryptPasswordEncoder.class, passwordEncoder.getClass());
        WebMvcErrorHandler errorHandler = context.getBean(WebMvcErrorHandler.class);
        assertNotNull(errorHandler);        
        AbstractUserDetailsService<CustomUser> userDetailsService = context.getBean(AbstractUserDetailsService.class);
        UserDetails user = userDetailsService.loadUserByUsername("jaja");
        assertTrue(user.isAccountNonExpired());
        assertTrue(user.isAccountNonLocked());
    }
    
    @Test
    public void autoConfig_shouldConfigureSecurity_withCrowd() {
        loadApplicationContext();
        AuthenticationManager delegatingManager = context.getBean(AuthenticationManager.class);
        AuthenticationManagerBuilder authManagerBuilder = (AuthenticationManagerBuilder) getField(delegatingManager, "delegateBuilder");
        ProviderManager authManager = (ProviderManager) getField(authManagerBuilder.getObject(), "parent");
        assertEquals(1, authManager.getProviders().size());
        assertEquals(RemoteCrowdAuthenticationProvider.class, authManager.getProviders().get(0).getClass());        
    }
    
    @Test
    public void authenticate_shouldSucceed_withNoOpPasswordEncoder() {
        loadApplicationContext(ConfigWithCustomPasswordEncoder.class);
        AuthenticationManager authManager = context.getBean(AuthenticationManager.class);
        Authentication auth = authManager.authenticate(new UsernamePasswordAuthenticationToken("user", "password"));
        assertEquals("custom", auth.getName());
        assertEquals("ROLE_ADMIN", auth.getAuthorities().iterator().next().getAuthority());
    }
    
    @Test
    public void authenticate_shouldSucceed_withInMemoryUserStore() {
        loadApplicationContext(ConfigWithInMemoryUserStore.class);
        AuthenticationManager authManager = context.getBean(AuthenticationManager.class);
        Authentication auth = authManager.authenticate(new UsernamePasswordAuthenticationToken("piet", "secret"));
        assertEquals("piet", auth.getName());
        assertEquals("ROLE_USER", auth.getAuthorities().iterator().next().getAuthority());
    }
    
    @Test(expected = BadCredentialsException.class)
    public void authenticate_shouldFail_withDefaultPasswordEncoder() {
        loadApplicationContext(ConfigWithUserDetailsService.class);
        AuthenticationManager authManager = context.getBean(AuthenticationManager.class);
        authManager.authenticate(new UsernamePasswordAuthenticationToken("user", "password"));
    }
    
    @Configuration    
    static class ConfigWithUserDetailsService {
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
        
    static class ConfigWithCustomPasswordEncoder extends ConfigWithUserDetailsService {
        @Bean
        public PasswordEncoder passwordEncoder() {
            return NoOpPasswordEncoder.getInstance();
        }
    }

    @Configuration
    static class ConfigWithInMemoryUserStore {
        @Bean
        public InMemoryUsersStore userStore() {
            return new InMemoryUsersStore() {

                @Override
                public List<RegisteredUser> users() {
                    return asList(new RegisteredUser() {
                        @Override
                        public String getUsername() {
                            return "piet";
                        }
                        
                        @Override
                        public List<String> getRolesAsString() {
                            return asList("USER");
                        }
                        
                        @Override
                        public String getPassword() {
                            return "secret";
                        }
                    });
                }
                
            };
        }
    }
    
    public static class CustomUser implements RegisteredUser {

        @Override
        public String getUsername() {
            return "custom";
        }

        @Override
        public String getPassword() {
            return "password";
        }

        @Override
        public List<String> getRolesAsString() {
            return asList("ADMIN");
        }
        
        public boolean accountNonExpired() {
            return false;
        }
    }
    
    private void loadApplicationContext(String... env) {
        loadApplicationContext(null, env);
    }

    private void loadApplicationContext(Class<?> config, String... env) {
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
