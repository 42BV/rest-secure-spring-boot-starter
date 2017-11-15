package nl._42.restsecure.autoconfigure.userdetails.crowd;

import java.util.HashMap;
import java.util.Map;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("rest-secure")
public class RestSecureProperties {

    /**
     * Mappings from crowd group name to application role.
     */
    private Map<String, String> crowdGroupToAuthorityMappings = new HashMap<>();

    public Map<String, String> getCrowdGroupToAuthorityMappings() {
        return crowdGroupToAuthorityMappings;
    }

    public void setCrowdGroupToAuthorityMappings(Map<String, String> crowdGroupToAuthorityMappings) {
        this.crowdGroupToAuthorityMappings = crowdGroupToAuthorityMappings;
    }
}
