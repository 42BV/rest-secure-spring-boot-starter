package nl._42.restsecure.autoconfigure.userdetails;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public abstract class AbstractUserDetailsService<T extends RegisteredUser> implements UserDetailsService {

    @Autowired(required = false)
    private AccountExpiredResolver<T> accountExpiredRepo;
    @Autowired(required = false)
    private AccountLockedResolver<T> accountLockedRepo;
    @Autowired(required = false)
    private CredentialsExpiredResolver<T> credentialsExpiredRepo;
    @Autowired(required = false)
    private UserEnabledResolver<T>  enabledRepo;
    
    protected abstract T findUserByUsername(String username);
    
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        T user = findUserByUsername(username);
        if (user == null) {
            throw new UsernameNotFoundException("Username: '" + username + "' not found.");
        }
        return new UserDetailsAdapter<T>(user, accountExpiredRepo, accountLockedRepo, credentialsExpiredRepo, enabledRepo);
    }
}
