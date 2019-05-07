package nl._42.restsecure.autoconfigure;

import java.util.Map.Entry;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnResource;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.atlassian.crowd.integration.http.CrowdHttpAuthenticatorImpl;
import com.atlassian.crowd.integration.http.util.CrowdHttpTokenHelperImpl;
import com.atlassian.crowd.integration.http.util.CrowdHttpValidationFactorExtractorImpl;
import com.atlassian.crowd.integration.rest.service.factory.RestCrowdClientFactory;
import com.atlassian.crowd.integration.springsecurity.RemoteCrowdAuthenticationProvider;
import com.atlassian.crowd.integration.springsecurity.user.CrowdUserDetailsService;
import com.atlassian.crowd.integration.springsecurity.user.CrowdUserDetailsServiceImpl;
import com.atlassian.crowd.service.client.ClientPropertiesImpl;
import com.atlassian.crowd.service.client.CrowdClient;

/**
 * Autoconfigures Crowd when a crowd-integration-springsecurity jar is found on the application's classpath.
 * When a crowd-group-to-role property is found within the application properties, these mappings will be used by the {@link CrowdUserDetailsService}
 */
@ConditionalOnResource(resources = { "classpath:/applicationContext-CrowdRestClient.xml" })
@Configuration
@EnableConfigurationProperties(RestSecureProperties.class)
public class CrowdAuthenticationAutoConfig {

    private final Logger log = LoggerFactory.getLogger(CrowdAuthenticationAutoConfig.class);

    @Autowired
    private RestSecureProperties props;

    @Bean
    public ClientPropertiesImpl clientProperties() {
        return ClientPropertiesImpl.newInstanceFromProperties(props.getCrowdProperties());
    }

    @Bean
    public CrowdClient crowdClient() {
        return new RestCrowdClientFactory().newInstance(clientProperties());
    }

    @Bean
    public RemoteCrowdAuthenticationProvider crowdAuthenticationProvider() {
        return new RemoteCrowdAuthenticationProvider(crowdClient(), new CrowdHttpAuthenticatorImpl(crowdClient(), clientProperties(),
                CrowdHttpTokenHelperImpl.getInstance(CrowdHttpValidationFactorExtractorImpl.getInstance())), crowdUserDetailsService());
    }

    @Bean
    public CrowdUserDetailsService crowdUserDetailsService() {
        CrowdUserDetailsServiceImpl crowdUserDetailsService = new CrowdUserDetailsServiceImpl();
        crowdUserDetailsService.setCrowdClient(crowdClient());
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
