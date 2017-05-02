package nl._42.restsecure.autoconfigure;

import static java.util.Arrays.asList;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.springframework.boot.test.util.EnvironmentTestUtils.addEnvironment;

import java.util.List;

import org.junit.After;
import org.junit.Assert;
import org.junit.Test;
import org.springframework.boot.autoconfigure.jackson.JacksonAutoConfiguration;
import org.springframework.boot.autoconfigure.web.HttpMessageConvertersAutoConfiguration;
import org.springframework.boot.autoconfigure.web.WebMvcAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.StandardPasswordEncoder;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;

import com.atlassian.crowd.service.AuthenticationManager;
import com.atlassian.crowd.service.cache.CacheAwareAuthenticationManager;

import nl._42.restsecure.autoconfigure.components.WebMvcErrorHandler;
import nl._42.restsecure.autoconfigure.userdetails.AbstractUserDetailsService;
import nl._42.restsecure.autoconfigure.userdetails.AccountExpiredResolver;
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
        AbstractUserDetailsService userDetailsService = context.getBean(AbstractUserDetailsService.class);
        UserDetails user = userDetailsService.loadUserByUsername("jaja");
        assertTrue(user.isAccountNonExpired());
        assertTrue(user.isAccountNonLocked());
    }
    
    @Test
    public void autoConfig_shouldConfigureSecurity_withProvidedPasswordEncoder() {
        loadApplicationContext(ConfigWithCustomPasswordEncoder.class);
        PasswordEncoder passwordEncoder = context.getBean(PasswordEncoder.class);
        assertEquals(StandardPasswordEncoder.class, passwordEncoder.getClass());
    }
    
    @Test
    public void autoConfig_shouldConfigureSecurity_withCustomAccountExpiredRepo() {
        loadApplicationContext(ConfigWithCustomAccountExpiredRepository.class);
        AbstractUserDetailsService userDetailsService = context.getBean(AbstractUserDetailsService.class);
        UserDetails user = userDetailsService.loadUserByUsername("jaja");
        assertFalse(user.isAccountNonExpired());
        assertTrue(user.isAccountNonLocked());
    }
    
    @Test
    public void autoConfig_shouldConfigureSecurity_withCrowd() {
        loadApplicationContext();
        AuthenticationManager authManager = context.getBean(AuthenticationManager.class);
        Assert.assertEquals(CacheAwareAuthenticationManager.class, authManager.getClass());
    }
    
    @Configuration    
    static class ConfigWithUserDetailsService {
        @Bean
        public AbstractUserDetailsService userDetailsService() {
            return new AbstractUserDetailsService() {                
                @Override
                public RegisteredUser findUserByUsername(String username) {
                    return new CustomUser();
                }
            };
        }
    }
    
    static class ConfigWithCustomAccountExpiredRepository extends ConfigWithUserDetailsService {
        @Bean
        public AccountExpiredResolver<CustomUser> accountExpiredRepository() {
            return new AccountExpiredResolver<CustomUser>() {

                @Override
                public boolean isAccountNonExpired(CustomUser user) {
                    return user.accountNonExpired();
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
            return "*****";
        }

        @Override
        public List<String> getRoles() {
            return asList("ADMIN");
        }
        
        public boolean accountNonExpired() {
            return false;
        }
    }
    
    static class ConfigWithCustomPasswordEncoder extends ConfigWithUserDetailsService {
        @Bean
        public PasswordEncoder passwordEncoder() {
            return new StandardPasswordEncoder();
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
