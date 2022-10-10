package nl._42.restsecure.autoconfigure;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.function.Supplier;

import nl._42.restsecure.autoconfigure.authentication.AuthenticationAdapter;
import nl._42.restsecure.autoconfigure.authentication.RegisteredUser;
import nl._42.restsecure.autoconfigure.authentication.User;
import nl._42.restsecure.autoconfigure.test.MethodSecurityConfig;
import nl._42.restsecure.autoconfigure.test.SecuredService;

import org.junit.jupiter.api.Test;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

class MethodSecurityTest extends AbstractApplicationContextTest {

    @Test
    void everybody_shouldSucceed() {
        SecuredService securedService = getSecuredService();
        assertTrue(securedService.everybody());
    }

    @Test
    void authenticated_shouldSucceed_whenLoggedIn() {
        SecuredService securedService = getSecuredService();

        User user = new User("user", "ROLE_user");
        assertTrue(runAs(user, securedService::authenticated));
    }

    @Test
    void authenticated_shouldFail_whenAnonymous() {
        SecuredService securedService = getSecuredService();
        assertThrows(AuthenticationCredentialsNotFoundException.class, securedService::authenticated);
    }

    @Test
    void admin_shouldSucceed_whenAdmin() {
        SecuredService securedService = getSecuredService();

        User admin = new User("admin", "ROLE_admin");
        assertTrue(runAs(admin, securedService::admin));
    }

    @Test
    void admin_shouldFail_whenUser() {
        SecuredService securedService = getSecuredService();

        User user = new User("user", "ROLE_user");
        assertThrows(AccessDeniedException.class, () -> runAs(user, securedService::admin));
    }

    @Test
    void admin_shouldFail_whenAnonymous() {
        SecuredService securedService = getSecuredService();
        assertThrows(AuthenticationCredentialsNotFoundException.class, securedService::admin);
    }

    private <T> T runAs(RegisteredUser user, Supplier<T> supplier) {
        SecurityContext context = SecurityContextHolder.getContext();
        Authentication authentication = context.getAuthentication();

        try {
            context.setAuthentication(new AuthenticationAdapter(user));
            return supplier.get();
        } finally {
            context.setAuthentication(authentication);
        }
    }

    private SecuredService getSecuredService() {
        SecurityContextHolder.clearContext();
        loadApplicationContext(MethodSecurityConfig.class);
        this.context.refresh();
        return context.getBean(SecuredService.class);
    }

}
