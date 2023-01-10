package nl._42.restsecure.autoconfigure.errorhandling;

import static nl._42.restsecure.autoconfigure.errorhandling.RestAccessDeniedHandler.SERVER_ACCESS_DENIED_ERROR;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import nl._42.restsecure.autoconfigure.AbstractApplicationContextTest;
import nl._42.restsecure.autoconfigure.test.RestrictedEndpointsConfig;

import org.junit.jupiter.api.Test;

public class WebMvcErrorHandlingTest extends AbstractApplicationContextTest {

    @Test
    public void forbiddenEndpoint_shouldFail_whenAdmin() throws Exception {
        getWebClient(RestrictedEndpointsConfig.class)
                .perform(get("/test/preauthorized"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("errorCode").value(SERVER_ACCESS_DENIED_ERROR));
    }
}
