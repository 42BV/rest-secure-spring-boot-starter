package nl._42.restsecure.autoconfigure.shared.test;

import java.util.Set;

import nl._42.restsecure.autoconfigure.userdetails.AbstractUserDetailsService;
import nl._42.restsecure.autoconfigure.userdetails.RegisteredUser;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.google.common.collect.Sets;

@Configuration
public class UserDetailsServiceConfig {
    
    @Bean
    public AbstractUserDetailsService<CustomUser> userDetailsService() {
        return new AbstractUserDetailsService<CustomUser>() {                
            @Override
            public CustomUser findUserByUsername(String username) {
                return createUser();
            }
        };
    }
    
    public static CustomUser createUser() {
        return new CustomUser();
    }
    
    public static class CustomUser implements RegisteredUser {

        @Override
        public String getUsername() {
            return "username";
        }

        @Override
        public String getPassword() {
            return "password";
        }

        @Override
        public Set<String> getAuthorities() {
            return Sets.newHashSet("ROLE_ADMIN");
        }
    }
}
