package nl._42.restsecure.autoconfigure.iface;

import java.util.Collection;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

public class UserDetailsAdapter implements UserDetails {

    private final RegisteredUser user;
    private final AccountExpiredRepository accountExpiredRepo;
    private final AccountLockedRepository accountLockedRepo;
    private final CredentialsExpiredRepository credentialsExpiredRepo;
    private final UserEnabledRepository userEnabledRepo;
    
    public UserDetailsAdapter(RegisteredUser user, 
            AccountExpiredRepository accountExpiredRepo, 
            AccountLockedRepository accountLockedRepo, 
            CredentialsExpiredRepository credentialsExpiredRepo, 
            UserEnabledRepository userEnabledRepo) {
        this.user = user;
        this.accountExpiredRepo = accountExpiredRepo;
        this.accountLockedRepo = accountLockedRepo;
        this.credentialsExpiredRepo = credentialsExpiredRepo;
        this.userEnabledRepo = userEnabledRepo;
    }
    
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return user.getRoles().stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role.toString()))
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
