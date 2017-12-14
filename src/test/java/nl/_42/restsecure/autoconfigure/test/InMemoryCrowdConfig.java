package nl._42.restsecure.autoconfigure.test;

import static com.google.common.collect.Sets.newHashSet;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.annotation.PostConstruct;

import nl._42.restsecure.autoconfigure.userdetails.AbstractUserDetailsService;
import nl._42.restsecure.autoconfigure.userdetails.CrowdUser;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class InMemoryCrowdConfig {
    
    @Bean
    public AbstractUserDetailsService<CrowdUser> userDetailsService() {
        return new AbstractUserDetailsService<CrowdUser>() {
            private Map<String, CrowdUser> users = new ConcurrentHashMap<>();
            @PostConstruct
            private void initUserStore() {
                users.put("janAdmin", new CrowdUser("janAdmin", "secret", newHashSet("ROLE_ADMIN")));
                users.put("janUser", new CrowdUser("janUser", "secret", newHashSet("ROLE_USER")));
            }
            @Override
            protected CrowdUser findUserByUsername(String username) {
                return users.get(username);
            }
        };
    }
}
