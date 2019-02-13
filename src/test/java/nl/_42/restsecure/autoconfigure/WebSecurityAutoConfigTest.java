package nl._42.restsecure.autoconfigure;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.springframework.test.util.ReflectionTestUtils.getField;

import nl._42.restsecure.autoconfigure.authentication.AbstractUserDetailsService;
import nl._42.restsecure.autoconfigure.authentication.RegisteredUser;
import nl._42.restsecure.autoconfigure.errorhandling.WebMvcErrorHandler;
import nl._42.restsecure.autoconfigure.test.ActiveUserConfig;
import nl._42.restsecure.autoconfigure.test.NullCrowdAuthenticationProviderConfig;

import org.junit.Test;
import org.springframework.beans.factory.BeanCreationException;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.http.HttpMessageConvertersAutoConfiguration;
import org.springframework.boot.autoconfigure.jackson.JacksonAutoConfiguration;
import org.springframework.boot.autoconfigure.web.servlet.WebMvcAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.atlassian.crowd.integration.springsecurity.RemoteCrowdAuthenticationProvider;

public class WebSecurityAutoConfigTest extends AbstractApplicationContextTest {

    @Test
    public void autoConfig_shouldConfigureSecurity_withDefaults() {
        loadApplicationContext(ActiveUserConfig.class);
        PasswordEncoder passwordEncoder = context.getBean(PasswordEncoder.class);
        assertEquals("PasswordEncoder should be a BCryptPasswordEncoder.", BCryptPasswordEncoder.class, passwordEncoder.getClass());
        WebMvcErrorHandler errorHandler = context.getBean(WebMvcErrorHandler.class);
        assertNotNull("WebMvcErrorHandler should be part of the applicationContext.", errorHandler);        
        AbstractUserDetailsService<RegisteredUser> userDetailsService = context.getBean(AbstractUserDetailsService.class);
        UserDetails user = userDetailsService.loadUserByUsername("jaja");
        assertTrue("User returned by userDetailsService should have account non expired.", user.isAccountNonExpired());
        assertTrue("User returned by userDetailsService should have account non locked.", user.isAccountNonLocked());
    }
    
    @Test
    public void autoConfig_shouldConfigureSecurity_withCrowd() {
        new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(WebMvcAutoConfiguration.class,
                        CrowdAuthenticationAutoConfig.class,
                        JacksonAutoConfiguration.class,
                        HttpMessageConvertersAutoConfiguration.class,
                        WebSecurityAutoConfig.class))
                .withPropertyValues(
                        "rest-secure.authority-to-crowd-group-mappings.ROLE_ADMIN=crowd-admin-group",
                        "rest-secure.authority-to-crowd-group-mappings.ROLE_USER=crowd-user-group",
                        "rest-secure.crowd-properties.crowd.server.url=http://test.nl",
                        "rest-secure.crowd-properties.application.name=rest-secure")
                .run(ctx -> {
                    AuthenticationManager delegatingManager = ctx.getBean(AuthenticationManager.class);
                    AuthenticationManagerBuilder authManagerBuilder = (AuthenticationManagerBuilder) getField(delegatingManager, "delegateBuilder");
                    ProviderManager authManager = (ProviderManager) getField(authManagerBuilder.getObject(), "parent");
                    assertEquals("There should be one AuthenticationProvider configured.", 1, authManager.getProviders().size());
                    assertEquals("The AuthenticationProvider should be a RemoteCrowdAuthenticationProvider.", RemoteCrowdAuthenticationProvider.class,
                            authManager.getProviders().get(0).getClass());
                });
    }
    
    @Test(expected = BeanCreationException.class)
    public void autoConfig_shouldFail_withoutAuthenticationProvider() {
        loadApplicationContext();
        this.context.register(NullCrowdAuthenticationProviderConfig.class);
        this.context.refresh();
    }

}
