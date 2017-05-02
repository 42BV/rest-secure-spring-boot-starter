package nl._42.restsecure.autoconfigure.userdetails;

import java.util.Collection;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

public class UserDetailsAdapter implements UserDetails {

    public static final String ROLE_PREFIX = "ROLE_";
    
    private final RegisteredUser user;
    private final AccountExpiredResolver accountExpiredRepo;
    private final AccountLockedResolver accountLockedRepo;
    private final CredentialsExpiredResolver credentialsExpiredRepo;
    private final UserEnabledResolver userEnabledRepo;
    
    public UserDetailsAdapter(RegisteredUser user, 
            AccountExpiredResolver accountExpiredRepo, 
            AccountLockedResolver accountLockedRepo, 
            CredentialsExpiredResolver credentialsExpiredRepo, 
            UserEnabledResolver userEnabledRepo) {
        this.user = user;
        this.accountExpiredRepo = accountExpiredRepo;
        this.accountLockedRepo = accountLockedRepo;
        this.credentialsExpiredRepo = credentialsExpiredRepo;
        this.userEnabledRepo = userEnabledRepo;
    }
    
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return user.getRoles().stream()
                .map(role -> new SimpleGrantedAuthority(ROLE_PREFIX + role.toString()))
                .collect(Collectors.toSet());
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
