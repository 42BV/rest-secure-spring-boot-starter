package nl._42.restsecure.autoconfigure;

import java.util.Map.Entry;
import java.util.Set;

import nl._42.restsecure.autoconfigure.shared.RestSecureProperties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnResource;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportResource;
import org.springframework.security.authentication.AuthenticationProvider;

import com.atlassian.crowd.integration.http.HttpAuthenticator;
import com.atlassian.crowd.integration.http.VerifyTokenFilter;
import com.atlassian.crowd.integration.springsecurity.RemoteCrowdAuthenticationProvider;
import com.atlassian.crowd.integration.springsecurity.user.CrowdUserDetailsService;
import com.atlassian.crowd.integration.springsecurity.user.CrowdUserDetailsServiceImpl;
import com.atlassian.crowd.service.GroupMembershipManager;
import com.atlassian.crowd.service.UserManager;
import com.atlassian.crowd.service.cache.CacheAwareAuthenticationManager;

/**
 * Autoconfigures Crowd when a crowd-integration-springsecurity jar and a crowd.properties are found on the application's classpath.
 * When a crowd-group-to-role.properties is found on the application's classpath, these mappings will be used by the {@link CrowdUserDetailsService}
 */
@ConditionalOnResource(resources = { "classpath:/applicationContext-CrowdClient.xml", "classpath:/crowd.properties" })
@ImportResource("classpath:/applicationContext-CrowdClient.xml")
@Configuration
@EnableConfigurationProperties(RestSecureProperties.class)
public class CrowdAuthenticationAutoConfig {

    private final Logger log = LoggerFactory.getLogger(CrowdAuthenticationAutoConfig.class);

    @Autowired
    private HttpAuthenticator httpAuthenticator;
    @Autowired
    private GroupMembershipManager groupMembershipManager;
    @Autowired
    private CacheAwareAuthenticationManager crowdAuthenticationManager;
    @Autowired
    private UserManager userManager;
    @Autowired
    private RestSecureProperties props;

    @Bean
    public FilterRegistrationBean registration(VerifyTokenFilter filter) {
        FilterRegistrationBean registration = new FilterRegistrationBean(filter);
        registration.setEnabled(false);
        return registration;
    }

    @Bean
    public AuthenticationProvider crowdAuthenticationProvider() throws Exception {
        return new RemoteCrowdAuthenticationProvider(crowdAuthenticationManager, httpAuthenticator, crowdUserDetailsService());
    }

    @Bean
    public CrowdUserDetailsService crowdUserDetailsService() {
        CrowdUserDetailsServiceImpl crowdUserDetailsService = new CrowdUserDetailsServiceImpl();
        crowdUserDetailsService.setGroupMembershipManager(groupMembershipManager);
        crowdUserDetailsService.setUserManager(userManager);
        Set<Entry<String, String>> roleMappings = props.getCrowdGroupToAuthorityMappings();
        if (!roleMappings.isEmpty()) {
            log.info("Found rest-secure.authority-to-crowd-role-mappings in spring boot application properties.");
            roleMappings.forEach(roleMapping -> log.info("\t {}", roleMapping));
            crowdUserDetailsService.setGroupToAuthorityMappings(roleMappings);
        } else {
            log.warn(
                    "No rest-secure.authority-to-crowd-group-mappings in spring boot application properties found, no conversion of Crowd Groups will be applied!");
        }
        return crowdUserDetailsService;
    }
}
