package nl._42.restsecure.autoconfigure.errorhandling;

import static nl._42.restsecure.autoconfigure.errorhandling.RestAccessDeniedHandler.SERVER_ACCESS_DENIED_ERROR;
import static nl._42.restsecure.autoconfigure.errorhandling.RestAccessDeniedHandler.SERVER_AUTHENTICATE_ERROR;
import static nl._42.restsecure.autoconfigure.errorhandling.RestAccessDeniedHandler.SERVER_SESSION_INVALID_ERROR;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import nl._42.restsecure.autoconfigure.AbstractApplicationContextTest;
import nl._42.restsecure.autoconfigure.test.PermittedEndpointsConfig;
import nl._42.restsecure.autoconfigure.test.RestrictedEndpointsConfig;

import org.junit.jupiter.api.Test;

class WebMvcErrorHandlingTest extends AbstractApplicationContextTest {

    @Test
    void forbiddenEndpoint_shouldFail_whenAdmin() throws Exception {
        getWebClient(RestrictedEndpointsConfig.class)
                .perform(get("/test/preauthorized"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("errorCode").value(SERVER_ACCESS_DENIED_ERROR));
    }

    @Test
    void preauthorizedEndpoint_shouldFailWithUnauthorized_whenAnonymousWithValidSession() throws Exception {
        getWebClientWithoutUser(PermittedEndpointsConfig.class)
                .perform(get("/test/preauthorized")
                        .with(request -> {
                            request.setRequestedSessionId("sessionid");
                            request.setRequestedSessionIdValid(true);
                            return request;
                        }))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("errorCode").value(SERVER_AUTHENTICATE_ERROR));
    }

    @Test
    void preauthorizedEndpoint_shouldFailWithUnauthorized_whenAnonymousWithInvalidSession() throws Exception {
        getWebClientWithoutUser(PermittedEndpointsConfig.class)
                .perform(get("/test/preauthorized")
                        .with(request -> {
                            request.setRequestedSessionId("sessionid");
                            request.setRequestedSessionIdValid(false);
                            return request;
                        }))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("errorCode").value(SERVER_SESSION_INVALID_ERROR));
    }
}
