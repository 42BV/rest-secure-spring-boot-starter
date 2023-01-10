package nl._42.restsecure.autoconfigure.authentication;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Collections;

import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

class DefaultUserProviderTest {

    private final UserProvider provider = new DefaultUserProvider();

    @Test
    void to_user() {
        GrantedAuthority admin = new SimpleGrantedAuthority("admin");
        Authentication authentication = new UsernamePasswordAuthenticationToken("henk", "password", Collections.singleton(admin));

        RegisteredUser user = provider.toUser(authentication);
        assertEquals("henk", user.getUsername());
        assertEquals("", user.getPassword());
        assertEquals(Collections.singleton("admin"), user.getAuthorities());
        assertFalse(user.isAccountExpired());
        assertFalse(user.isAccountLocked());
        assertFalse(user.isCredentialsExpired());
        assertTrue(user.isEnabled());
    }
}
