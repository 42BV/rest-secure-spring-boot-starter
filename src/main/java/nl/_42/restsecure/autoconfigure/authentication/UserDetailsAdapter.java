package nl._42.restsecure.autoconfigure.authentication;

import static java.util.stream.Collectors.toSet;

import java.util.Collection;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * Wraps the custom user object and will be available as principal on the {@link Authentication} in the {@link SecurityContext}.
 *
 * @param <T> the type of the custom user.
 */
public record UserDetailsAdapter<T extends RegisteredUser>(T user) implements UserDetails {

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return user.getAuthorities().stream()
                .map(SimpleGrantedAuthority::new)
                .collect(toSet());
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return !user.isAccountExpired();
    }

    @Override
    public boolean isAccountNonLocked() {
        return !user.isAccountLocked();
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return !user.isCredentialsExpired();
    }

    @Override
    public boolean isEnabled() {
        return user.isEnabled();
    }

    public boolean isMfaConfigured() {
        return user.isMfaConfigured();
    }

    public boolean isMfaMandatory() {
        return user.isMfaMandatory();
    }
}
