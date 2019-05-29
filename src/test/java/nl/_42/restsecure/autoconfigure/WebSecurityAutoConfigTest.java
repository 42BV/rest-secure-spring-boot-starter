package nl._42.restsecure.autoconfigure;

import nl._42.restsecure.autoconfigure.errorhandling.WebMvcErrorHandler;
import nl._42.restsecure.autoconfigure.test.ActiveUserConfig;
import nl._42.restsecure.autoconfigure.test.AuthenticationProviderConfig;
import nl._42.restsecure.autoconfigure.test.NullAuthenticationProviderConfig;
import org.junit.Test;
import org.springframework.beans.factory.BeanCreationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class WebSecurityAutoConfigTest extends AbstractApplicationContextTest {

    @Test
    public void autoConfig_shouldConfigureSecurity_withService() {
        loadApplicationContext(ActiveUserConfig.class);
        this.context.refresh();

        PasswordEncoder passwordEncoder = context.getBean(PasswordEncoder.class);
        assertEquals("PasswordEncoder should be a BCryptPasswordEncoder.", BCryptPasswordEncoder.class, passwordEncoder.getClass());

        WebMvcErrorHandler errorHandler = context.getBean(WebMvcErrorHandler.class);
        assertNotNull("WebMvcErrorHandler should be part of the applicationContext.", errorHandler);

        UserDetailsService userDetailsService = context.getBean(UserDetailsService.class);
        UserDetails user = userDetailsService.loadUserByUsername("jaja");
        assertTrue("User returned by userDetailsService should have account non expired.", user.isAccountNonExpired());
        assertTrue("User returned by userDetailsService should have account non locked.", user.isAccountNonLocked());
    }

    @Test
    public void autoConfig_shouldConfigureSecurity_withProvider() {
        loadApplicationContext(AuthenticationProviderConfig.class);
        this.context.refresh();
    }

    @Test(expected = BeanCreationException.class)
    public void autoConfig_shouldFail_withoutAuthenticationProvider() {
        loadApplicationContext(NullAuthenticationProviderConfig.class);
        this.context.refresh();
    }

}
