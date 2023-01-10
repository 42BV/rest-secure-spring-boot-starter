package nl._42.restsecure.autoconfigure.authentication;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Collections;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

class AuthenticationAdapterTest {

    @Test
    void getCredentials_shouldAlwaysBeEmpty() {
        User user = new User("henk", "admin");

        Authentication authentication = new AuthenticationAdapter(user);
        assertEquals("", authentication.getCredentials());
    }

    @Test
    void getAuthorities_shouldSucceed() {
        User user = new User("henk", "admin");

        Authentication authentication = new AuthenticationAdapter(user);
        assertEquals(Collections.singletonList(
                new SimpleGrantedAuthority("admin")
        ), authentication.getAuthorities());
    }

    @Test
    void getPrincipal_shouldSucceed() {
        User user = new User("henk", "admin");

        Authentication authentication = new AuthenticationAdapter(user);
        Object principal = authentication.getPrincipal();

        assertEquals(UserDetailsAdapter.class, principal.getClass());
        assertEquals(user, ((UserDetailsAdapter<?>) principal).user());
    }

}
