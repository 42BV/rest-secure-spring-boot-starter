package nl._42.restsecure.autoconfigure.components;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.anonymous;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import nl._42.restsecure.autoconfigure.shared.test.AbstractApplicationContextTest;
import nl._42.restsecure.autoconfigure.shared.test.config.AuthenticationResultProviderConfig;
import nl._42.restsecure.autoconfigure.shared.test.config.InMemoryCrowdConfig;
import nl._42.restsecure.autoconfigure.shared.test.config.MockedCrowdAuthenticationProviderConfig;
import nl._42.restsecure.autoconfigure.shared.test.config.NoopPasswordEncoderConfig;
import nl._42.restsecure.autoconfigure.shared.test.config.UserDetailsServiceConfig;

import org.junit.Test;

public class AuthenticationControllerTest extends AbstractApplicationContextTest {

    @Test
    public void currentUser_shouldFail_whenNotLoggedIn() throws Exception {
        getWebClient(UserDetailsServiceConfig.class)
            .perform(get("/authentication/current")
                .with(anonymous()))
            .andExpect(status().isUnauthorized());
    }

    @Test
    public void currentUser_shouldSucceed_whenLoggedIn() throws Exception {
        getWebClient(UserDetailsServiceConfig.class)
            .perform(get("/authentication/current"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("authorities[0]").value("ROLE_ADMIN"))
            .andExpect(jsonPath("username").value("username"));
    }

    @Test
    public void currentUser_shouldReturnCustomAuthenticationResult_withCustomAuthenticationResultProvider() throws Exception {
        getWebClient(AuthenticationResultProviderConfig.class)
            .perform(get("/authentication/current"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("authorities[0]").value("ROLE_ADMIN"))
            .andExpect(jsonPath("username").value("customized"));
    }

    @Test
    public void authenticate_shouldSucceed_withCorrectCredentials() throws Exception {
        getWebClient(UserDetailsServiceConfig.class, NoopPasswordEncoderConfig.class)
            .perform(post("/authentication")
                .content("{\"username\": \"custom\", \"password\": \"password\"}"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("authorities[0]").value("ROLE_ADMIN"))
            .andExpect(jsonPath("username").value("username"));
    }

    @Test
    public void authenticate_shouldSucceed_whenUsingInMemoryCrowdUsers() throws Exception {
        getWebClient(InMemoryCrowdConfig.class, NoopPasswordEncoderConfig.class)
            .perform(post("/authentication")
                .content("{\"username\": \"janUser\", \"password\": \"secret\"}"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("authorities[0]").value("ROLE_USER"))
            .andExpect(jsonPath("username").value("janUser"));
    }

    @Test
    public void authenticate_shouldSucceed_whenUsingMockedCrowdAuthenticationProvider() throws Exception {
        getWebClient(InMemoryCrowdConfig.class, MockedCrowdAuthenticationProviderConfig.class)
            .perform(post("/authentication")
                .content("{\"username\": \"crowdUser\", \"password\": \"crowdPassword\"}"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("authorities[0]").value("ROLE_USER"))
            .andExpect(jsonPath("username").value("crowdUser"));
    }

    @Test
    public void authenticate_shouldFail_withCorrectCredentials_butBrcyptPasswordEncoder() throws Exception {
        getWebClient(UserDetailsServiceConfig.class)
            .perform(post("/authentication")
                .content("{\"username\": \"custom\", \"password\": \"password\"}"))
            .andExpect(status().isUnauthorized());
    }

    @Test
    public void handshake_shouldReturnCsrfToken() throws Exception {
        getWebClient(UserDetailsServiceConfig.class)
            .perform(get("/authentication/handshake"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("csrfToken").exists());
    }
}
