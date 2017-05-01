package nl._42.restsecure.autoconfigure;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.springframework.boot.test.util.EnvironmentTestUtils.addEnvironment;

import org.junit.After;
import org.junit.Test;
import org.springframework.boot.autoconfigure.jackson.JacksonAutoConfiguration;
import org.springframework.boot.autoconfigure.web.HttpMessageConvertersAutoConfiguration;
import org.springframework.boot.autoconfigure.web.WebMvcAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.StandardPasswordEncoder;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;

import nl._42.restsecure.autoconfigure.component.WebMvcErrorHandler;
import nl._42.restsecure.autoconfigure.iface.AbstractUserDetailsService;
import nl._42.restsecure.autoconfigure.iface.RegisteredUser;

public class WebSecurityAutoConfigTest {

    private AnnotationConfigWebApplicationContext context;

    @After
    public void tearDown() {
        if (this.context != null) {
            this.context.close();
        }
    }
    
    @Test
    public void autoConfig_shouldConfigureSecurity() {
        loadApplicationContext(ConfigWithUserDetailsService.class);
        PasswordEncoder passwordEncoder = context.getBean(PasswordEncoder.class);
        assertEquals(BCryptPasswordEncoder.class, passwordEncoder.getClass());
        WebMvcErrorHandler errorHandler = context.getBean(WebMvcErrorHandler.class);
        assertNotNull(errorHandler);
    }
    
    @Test
    public void autoConfig_shouldConfigureSecurity_withProvidedPasswordEncoder() {
        loadApplicationContext(ConfigWithCustomPasswordEncoder.class);
        PasswordEncoder passwordEncoder = context.getBean(PasswordEncoder.class);
        assertEquals(StandardPasswordEncoder.class, passwordEncoder.getClass());
    }
    
    @Configuration
    static class ConfigWithUserDetailsService {
        @Bean
        public AbstractUserDetailsService userDetailsService() {
            return new AbstractUserDetailsService() {                
                @Override
                public RegisteredUser findUserByUsername(String username) {
                    return null;
                }
            };
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
