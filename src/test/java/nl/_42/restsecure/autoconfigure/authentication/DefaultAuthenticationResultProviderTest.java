package nl._42.restsecure.autoconfigure.authentication;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class DefaultAuthenticationResultProviderTest {

    private final AuthenticationResultProvider<RegisteredUser> provider = new DefaultAuthenticationResultProvider();

    @Test
    void to_result() {
        User user = new User("henk", "admin");

        AuthenticationResult result = provider.toResult(null, null, user);
        assertEquals("henk", result.getUsername());
        assertEquals(user.getAuthorities(), result.getAuthorities());
    }
}
