package nl._42.restsecure.autoconfigure;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import nl._42.restsecure.autoconfigure.authentication.mfa.MfaAuthenticationProvider;
import nl._42.restsecure.autoconfigure.authentication.mfa.MfaValidationService;
import nl._42.restsecure.autoconfigure.authentication.mfa.MfaValidationServiceImpl;
import nl._42.restsecure.autoconfigure.errorhandling.WebMvcErrorHandler;
import nl._42.restsecure.autoconfigure.test.ActiveUserAndMfaConfig;
import nl._42.restsecure.autoconfigure.test.ActiveUserConfig;
import nl._42.restsecure.autoconfigure.test.AuthenticationProviderConfig;
import nl._42.restsecure.autoconfigure.test.NullAuthenticationProviderConfig;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.BeanCreationException;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

class WebSecurityAutoConfigTest extends AbstractApplicationContextTest {

    @Test
    void autoConfig_shouldConfigureSecurity_withService() {
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
    void autoConfig_shouldConfigureSecurity_withServiceAndMfaProvider_shouldNotGenerateDaoAuthenticationProvider() {
        loadApplicationContext(ActiveUserAndMfaConfig.class);
        this.context.refresh();

        PasswordEncoder passwordEncoder = context.getBean(PasswordEncoder.class);
        assertEquals(BCryptPasswordEncoder.class, passwordEncoder.getClass());

        WebMvcErrorHandler errorHandler = context.getBean(WebMvcErrorHandler.class);
        assertNotNull(errorHandler);

        UserDetailsService userDetailsService = context.getBean(UserDetailsService.class);
        UserDetails user = userDetailsService.loadUserByUsername("jaja");
        assertTrue(user.isAccountNonExpired());
        assertTrue(user.isAccountNonLocked());

        // Since the MFA provider extends from DaoAuthetnicationProvider, it will be returned.
        // But it *must* be an instance of the MFA provider and NOT the regular provider created by AuthenticationManagerBuilder.userDetailsService() !
        DaoAuthenticationProvider daoAuthenticationProvider = context.getBean(DaoAuthenticationProvider.class);
        assertEquals(MfaAuthenticationProvider.class, daoAuthenticationProvider.getClass());

        MfaValidationService mfaValidationService = context.getBean(MfaValidationService.class);
        assertEquals(MfaValidationServiceImpl.class, mfaValidationService.getClass());

        assertNotNull(context.getBean(MfaAuthenticationProvider.class));

    }

    @Test
    void autoConfig_shouldConfigureSecurity_withProvider() {
        loadApplicationContext(AuthenticationProviderConfig.class);
        this.context.refresh();

        assertNotNull(context.getBean(AuthenticationProvider.class));
    }

    @Test
    void autoConfig_shouldFail_withoutAuthenticationProvider() {
        assertThrows(BeanCreationException.class, () -> loadApplicationContext(NullAuthenticationProviderConfig.class));
    }

}
