package nl._42.restsecure.autoconfigure.userdetails;

import java.util.Collection;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

public class UserDetailsAdapter<T extends RegisteredUser> implements UserDetails {

    public static final String ROLE_PREFIX = "ROLE_";
    
    private final T user;
    private final AccountExpiredResolver<T> accountExpiredResolver;
    private final AccountLockedResolver<T> accountLockedResolver;
    private final CredentialsExpiredResolver<T> credentialsExpiredResolver;
    private final UserEnabledResolver<T> userEnabledResolver;
    
    public UserDetailsAdapter(T user, 
            AccountExpiredResolver<T> accountExpiredResolver, 
            AccountLockedResolver<T> accountLockedResolver, 
            CredentialsExpiredResolver<T> credentialsExpiredResolver, 
            UserEnabledResolver<T> userEnabledResolver) {
        super();
        this.user = user;
        this.accountExpiredResolver = accountExpiredResolver;
        this.accountLockedResolver = accountLockedResolver;
        this.credentialsExpiredResolver = credentialsExpiredResolver;
        this.userEnabledResolver = userEnabledResolver;
    }
    
    public UserDetailsAdapter(T user) {
        this(user, null, null, null, null);
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return user.getRolesAsString().stream()
                .map(role -> new SimpleGrantedAuthority(ROLE_PREFIX + role.toString()))
                .collect(Collectors.toSet());
    }

    public T getUser() {
        return user;
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
        return accountExpiredResolver == null ? true : accountExpiredResolver.isAccountNonExpired(user);
    }

    @Override
    public boolean isAccountNonLocked() {
        return accountLockedResolver == null ? true : accountLockedResolver.isAccountNonLocked(user);
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return credentialsExpiredResolver == null ? true : credentialsExpiredResolver.isCredentialsNonExpired(user);
    }

    @Override
    public boolean isEnabled() {
        return userEnabledResolver == null ? true : userEnabledResolver.isEnabled(user);
    }

}
