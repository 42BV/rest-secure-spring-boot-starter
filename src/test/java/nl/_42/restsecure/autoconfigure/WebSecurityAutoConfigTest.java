package nl._42.restsecure.autoconfigure;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import nl._42.restsecure.autoconfigure.errorhandling.WebMvcErrorHandler;
import nl._42.restsecure.autoconfigure.test.ActiveUserConfig;
import nl._42.restsecure.autoconfigure.test.AuthenticationProviderConfig;
import nl._42.restsecure.autoconfigure.test.NullAuthenticationProviderConfig;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.BeanCreationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

public class WebSecurityAutoConfigTest extends AbstractApplicationContextTest {

    @Test
    public void autoConfig_shouldConfigureSecurity_withService() {
        loadApplicationContext(ActiveUserConfig.class);
        this.context.refresh();

        PasswordEncoder passwordEncoder = context.getBean(PasswordEncoder.class);
        assertEquals(BCryptPasswordEncoder.class, passwordEncoder.getClass());

        WebMvcErrorHandler errorHandler = context.getBean(WebMvcErrorHandler.class);
        assertNotNull(errorHandler);

        UserDetailsService userDetailsService = context.getBean(UserDetailsService.class);
        UserDetails user = userDetailsService.loadUserByUsername("jaja");
        assertTrue(user.isAccountNonExpired());
        assertTrue(user.isAccountNonLocked());
    }

    @Test
    public void autoConfig_shouldConfigureSecurity_withProvider() {
        loadApplicationContext(AuthenticationProviderConfig.class);
        this.context.refresh();
    }

    @Test
    public void autoConfig_shouldFail_withoutAuthenticationProvider() {
        assertThrows(BeanCreationException.class, () -> loadApplicationContext(NullAuthenticationProviderConfig.class));
    }

}
