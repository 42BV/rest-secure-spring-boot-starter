package nl._42.restsecure.autoconfigure;

import static nl._42.restsecure.autoconfigure.RestAccessDeniedHandler.SERVER_ACCESS_DENIED_ERROR;
import static nl._42.restsecure.autoconfigure.RestAccessDeniedHandler.SERVER_AUTHENTICATE_ERROR;
import static nl._42.restsecure.autoconfigure.RestAccessDeniedHandler.SERVER_SESSION_INVALID_ERROR;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.log;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.setup.MockMvcBuilders.webAppContextSetup;

import javax.servlet.ServletContext;

import nl._42.restsecure.autoconfigure.shared.test.AbstractApplicationContextTest;
import nl._42.restsecure.autoconfigure.shared.test.config.ActiveUserConfig;
import nl._42.restsecure.autoconfigure.shared.test.config.RestrictedEndpointsConfig;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.web.servlet.RequestBuilder;

public class AccessDeniedHandlerTest extends AbstractApplicationContextTest {

    @Test
    public void forbiddenEndpoint_shouldFail_whenAdmin() throws Exception {
        getWebClient(RestrictedEndpointsConfig.class)
            .perform(get("/test/forbidden"))
            .andExpect(status().isForbidden())
            .andExpect(jsonPath("errorCode").value(SERVER_ACCESS_DENIED_ERROR));
    }
    
    @Test
    public void currentUser_shouldFail_withInvalidSession_whenNotLoggedIn() throws Exception {
        loadApplicationContext(ActiveUserConfig.class);
        webAppContextSetup(context)
            .apply(springSecurity())
            .build()
            .perform(new RequestBuilder() {
                @Override
                public MockHttpServletRequest buildRequest(ServletContext servletContext) {
                    MockHttpServletRequest request = get("/authentication/current")
                            .buildRequest(servletContext);
                    request.setRequestedSessionId("sessionid");
                    request.setRequestedSessionIdValid(false);
                    return request;
                }
            })
            .andDo(log())
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("errorCode").value(SERVER_SESSION_INVALID_ERROR));
    }

    @Test
    public void currentUser_shouldFail_withValidSession_whenNotLoggedIn() throws Exception {
        loadApplicationContext(ActiveUserConfig.class);
        webAppContextSetup(context)
            .apply(springSecurity())
            .build()
            .perform(new RequestBuilder() {
                @Override
                public MockHttpServletRequest buildRequest(ServletContext servletContext) {
                    MockHttpServletRequest request = get("/authentication/current")
                            .buildRequest(servletContext);
                    request.setRequestedSessionId("sessionid");
                    request.setRequestedSessionIdValid(true);
                    return request;
                }
            })
            .andDo(log())
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("errorCode").value(SERVER_AUTHENTICATE_ERROR));
    }
}
