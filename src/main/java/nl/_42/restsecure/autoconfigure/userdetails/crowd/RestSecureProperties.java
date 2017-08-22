package nl._42.restsecure.autoconfigure.userdetails.crowd;

import static java.util.stream.Collectors.toMap;
import static nl._42.restsecure.autoconfigure.userdetails.UserDetailsAdapter.ROLE_PREFIX;

import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("rest-secure")
public class RestSecureProperties {

    /**
     * Mappings from crowd group name to application role.
     */
    private Map<String, String> crowdGroupToRoleMappings = new HashMap<>();

    public Map<String, String> getCrowdGroupToRoleMappings() {
        return crowdGroupToRoleMappings;
    }

    public void setCrowdGroupToRoleMappings(Map<String, String> crowdGroupToRoleMappings) {
        this.crowdGroupToRoleMappings = crowdGroupToRoleMappings;
    }

    public Set<Entry<String, String>> convertedMappings() {
        return crowdGroupToRoleMappings.entrySet()
                .stream()
                .collect(toMap(Entry::getKey, e -> ROLE_PREFIX + e.getValue()))
                .entrySet();
    }
}
