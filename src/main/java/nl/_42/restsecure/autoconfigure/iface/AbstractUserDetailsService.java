package nl._42.restsecure.autoconfigure.iface;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public abstract class AbstractUserDetailsService implements UserDetailsService {

    @Autowired(required = false)
    private AccountExpiredResolver accountExpiredRepo;
    @Autowired(required = false)
    private AccountLockedResolver accountLockedRepo;
    @Autowired(required = false)
    private CredentialsExpiredResolver credentialsExpiredRepo;
    @Autowired(required = false)
    private UserEnabledResolver enabledRepo;
    
    protected abstract RegisteredUser findUserByUsername(String username);
    
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        RegisteredUser user = findUserByUsername(username);
        if (user == null) {
            throw new UsernameNotFoundException("Username: '" + username + "' not found.");
        }
        return new UserDetailsAdapter(user, accountExpiredRepo, accountLockedRepo, credentialsExpiredRepo, enabledRepo);
    }
}
