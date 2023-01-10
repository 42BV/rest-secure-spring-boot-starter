package nl._42.restsecure.autoconfigure.authentication;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Collections;

import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

class UserResolverTest {

    private final UserResolver<User> resolver = new UserResolver<>(
            new DefaultUserProvider()
    );

    @Test
    void resolve_adapter_shouldSucceed() {
        User user = new User("henk", "admin");
        Authentication authentication = new AuthenticationAdapter(user);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        assertEquals(user, resolver.resolve().orElseThrow(IllegalStateException::new));
    }

    @Test
    void resolve_authentication_shouldSucceed() {
        GrantedAuthority authority = new SimpleGrantedAuthority("admin");
        Authentication authentication = new UsernamePasswordAuthenticationToken("henk", "", Collections.singleton(authority));

        SecurityContextHolder.getContext().setAuthentication(authentication);
        RegisteredUser user = resolver.resolve().orElseThrow(IllegalStateException::new);
        assertEquals("henk", user.getUsername());
        assertEquals("", user.getPassword());
        assertEquals(Collections.singleton("admin"), user.getAuthorities());
    }
}
