package nl._42.restsecure.autoconfigure.userdetails;

import java.util.Collection;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

public class UserDetailsAdapter<T extends RegisteredUser> implements UserDetails {

    public static final String ROLE_PREFIX = "ROLE_";
    
    private final T user;
    private final AccountExpiredResolver<T> accountExpiredRepo;
    private final AccountLockedResolver<T> accountLockedRepo;
    private final CredentialsExpiredResolver<T> credentialsExpiredRepo;
    private final UserEnabledResolver<T> userEnabledRepo;
    
    public UserDetailsAdapter(T user, 
            AccountExpiredResolver<T> accountExpiredRepo, 
            AccountLockedResolver<T> accountLockedRepo, 
            CredentialsExpiredResolver<T> credentialsExpiredRepo, 
            UserEnabledResolver<T> userEnabledRepo) {
        this.user = user;
        this.accountExpiredRepo = accountExpiredRepo;
        this.accountLockedRepo = accountLockedRepo;
        this.credentialsExpiredRepo = credentialsExpiredRepo;
        this.userEnabledRepo = userEnabledRepo;
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
        return accountExpiredRepo == null ? true : accountExpiredRepo.isAccountNonExpired(user);
    }

    @Override
    public boolean isAccountNonLocked() {
        return accountLockedRepo == null ? true : accountLockedRepo.isAccountNonLocked(user);
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return credentialsExpiredRepo == null ? true : credentialsExpiredRepo.isCredentialsNonExpired(user);
    }

    @Override
    public boolean isEnabled() {
        return userEnabledRepo == null ? true : userEnabledRepo.isEnabled(user);
    }

}
