package nl._42.restsecure.autoconfigure.authentication;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class DefaultAuthenticationResultProviderTest {

    private final AuthenticationResultProvider<RegisteredUser> provider = new DefaultAuthenticationResultProvider();

    @Test
    void to_result() {
        User user = new User("henk", "admin");

        AuthenticationResult result = provider.toResult(null, null, user);
        assertTrue(result.isAuthenticated());
        assertEquals("henk", result.getUsername());
        assertEquals(user.getAuthorities(), result.getAuthorities());
    }

    @Test
    void to_result_whenUserIsNull_shouldReturnAnonymousResult() {
        AuthenticationResult result = provider.toResult(null, null, null);
        assertFalse(result.isAuthenticated());
        assertNull(result.getUsername());
        assertTrue(result.getAuthorities().isEmpty());
    }
}
