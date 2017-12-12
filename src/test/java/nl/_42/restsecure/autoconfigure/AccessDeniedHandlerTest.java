package nl._42.restsecure.autoconfigure;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import nl._42.restsecure.autoconfigure.shared.test.AbstractApplicationContextTest;
import nl._42.restsecure.autoconfigure.shared.test.config.RestrictedEndpointsConfig;

import org.junit.Test;

public class AccessDeniedHandlerTest extends AbstractApplicationContextTest {

    @Test
    public void forbiddenEndpoint_shouldFail_whenAdmin() throws Exception {
        getWebClient(RestrictedEndpointsConfig.class)
            .perform(get("/test/forbidden"))
            .andExpect(status().isForbidden());
    }

}
