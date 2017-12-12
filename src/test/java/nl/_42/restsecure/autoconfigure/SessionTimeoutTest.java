package nl._42.restsecure.autoconfigure;

import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.setup.MockMvcBuilders.webAppContextSetup;

import javax.servlet.ServletContext;

import nl._42.restsecure.autoconfigure.shared.test.AbstractApplicationContextTest;
import nl._42.restsecure.autoconfigure.shared.test.config.UserDetailsServiceConfig;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.web.servlet.RequestBuilder;

public class SessionTimeoutTest extends AbstractApplicationContextTest {

    @Test
    public void anyEndpoint_shouldFail_withInvalidSession() throws Exception {
        loadApplicationContext(UserDetailsServiceConfig.class);
        webAppContextSetup(context)
            .apply(springSecurity())
            .build()
            .perform(new RequestBuilder() {
                @Override
                public MockHttpServletRequest buildRequest(ServletContext servletContext) {
                    MockHttpServletRequest request = new MockHttpServletRequest();
                    request.setRequestedSessionId("sessionid");
                    request.setRequestedSessionIdValid(false);
                    return request;
                }
            })
            .andDo(print())
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("errorCode").value("SERVER.SESSION_TIMEOUT_ERROR"))
        ;
    }
}
