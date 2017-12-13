package nl._42.restsecure.autoconfigure;

import static nl._42.restsecure.autoconfigure.RestAccessDeniedHandler.SERVER_AUTHENTICATE_ERROR;
import static nl._42.restsecure.autoconfigure.RestAccessDeniedHandler.SERVER_SESSION_INVALID_ERROR;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.setup.MockMvcBuilders.webAppContextSetup;

import javax.servlet.ServletContext;

import nl._42.restsecure.autoconfigure.shared.test.AbstractApplicationContextTest;
import nl._42.restsecure.autoconfigure.shared.test.config.RestrictedEndpointsConfig;
import nl._42.restsecure.autoconfigure.shared.test.config.UserDetailsServiceConfig;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.web.servlet.RequestBuilder;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

public class AccessDeniedHandlerTest extends AbstractApplicationContextTest {

    @Test
    public void forbiddenEndpoint_shouldFail_whenAdmin() throws Exception {
        getWebClient(RestrictedEndpointsConfig.class)
            .perform(get("/test/forbidden"))
            .andExpect(status().isForbidden());
    }
    
    @Test
    public void currentUser_shouldFail_withInvalidSession_whenNotLoggedIn() throws Exception {
        loadApplicationContext(UserDetailsServiceConfig.class);
        webAppContextSetup(context)
            .apply(springSecurity())
            .build()
            .perform(new RequestBuilder() {
                @Override
                public MockHttpServletRequest buildRequest(ServletContext servletContext) {
                    MockHttpServletRequest request = MockMvcRequestBuilders
                            .get("/authentication/current")
                            .buildRequest(servletContext);
                    request.setRequestedSessionId("sessionid");
                    request.setRequestedSessionIdValid(false);
                    return request;
                }
            })
            .andDo(print())
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("errorCode").value(SERVER_SESSION_INVALID_ERROR));
    }

    @Test
    public void currentUser_shouldFail_withValidSession_whenNotLoggedIn() throws Exception {
        loadApplicationContext(UserDetailsServiceConfig.class);
        webAppContextSetup(context)
            .apply(springSecurity())
            .build()
            .perform(new RequestBuilder() {
                @Override
                public MockHttpServletRequest buildRequest(ServletContext servletContext) {
                    MockHttpServletRequest request = MockMvcRequestBuilders
                            .get("/authentication/current")
                            .buildRequest(servletContext);
                    request.setRequestedSessionId("sessionid");
                    request.setRequestedSessionIdValid(true);
                    return request;
                }
            })
            .andDo(print())
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("errorCode").value(SERVER_AUTHENTICATE_ERROR));
    }
}
