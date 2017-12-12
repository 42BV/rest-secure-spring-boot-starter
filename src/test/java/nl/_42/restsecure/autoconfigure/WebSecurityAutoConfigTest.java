package nl._42.restsecure.autoconfigure;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.springframework.test.util.ReflectionTestUtils.getField;

import nl._42.restsecure.autoconfigure.components.errorhandling.WebMvcErrorHandler;
import nl._42.restsecure.autoconfigure.shared.test.AbstractApplicationContextTest;
import nl._42.restsecure.autoconfigure.shared.test.config.UserDetailsServiceConfig;
import nl._42.restsecure.autoconfigure.userdetails.AbstractUserDetailsService;
import nl._42.restsecure.autoconfigure.userdetails.RegisteredUser;

import org.junit.Test;
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
        loadApplicationContext(UserDetailsServiceConfig.class);
        PasswordEncoder passwordEncoder = context.getBean(PasswordEncoder.class);
        assertEquals(BCryptPasswordEncoder.class, passwordEncoder.getClass());
        WebMvcErrorHandler errorHandler = context.getBean(WebMvcErrorHandler.class);
        assertNotNull(errorHandler);        
        AbstractUserDetailsService<RegisteredUser> userDetailsService = context.getBean(AbstractUserDetailsService.class);
        UserDetails user = userDetailsService.loadUserByUsername("jaja");
        assertTrue(user.isAccountNonExpired());
        assertTrue(user.isAccountNonLocked());
    }
    
    @Test
    public void autoConfig_shouldConfigureSecurity_withCrowd() {
        loadApplicationContext("rest-secure.authority-to-crowd-group-mappings.ROLE_ADMIN=crowd-admin-group",
                "rest-secure.authority-to-crowd-group-mappings.ROLE_USER=crowd-user-group");
        AuthenticationManager delegatingManager = context.getBean(AuthenticationManager.class);
        AuthenticationManagerBuilder authManagerBuilder = (AuthenticationManagerBuilder) getField(delegatingManager, "delegateBuilder");
        ProviderManager authManager = (ProviderManager) getField(authManagerBuilder.getObject(), "parent");
        assertEquals(1, authManager.getProviders().size());
        assertEquals(RemoteCrowdAuthenticationProvider.class, authManager.getProviders().get(0).getClass());        
    }

}
