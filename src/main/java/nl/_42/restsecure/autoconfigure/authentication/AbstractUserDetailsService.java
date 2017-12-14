package nl._42.restsecure.autoconfigure.authentication;

import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

/**
 * Implement this abstract class to configure for local user authentication storage.
 * Add your implementation as {@link Bean} to the {@link ApplicationContext}.
 *
 * @param <T> the user type that implements {@link RegisteredUser}.
 */
public abstract class AbstractUserDetailsService<T extends RegisteredUser> implements UserDetailsService {
    
    protected abstract T findUserByUsername(String username);
    
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        T user = findUserByUsername(username);
        if (user == null) {
            throw new UsernameNotFoundException("Username: '" + username + "' not found.");
        }
        return new UserDetailsAdapter<T>(user);
    }
}
