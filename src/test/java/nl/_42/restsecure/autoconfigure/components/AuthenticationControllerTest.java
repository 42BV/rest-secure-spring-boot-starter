package nl._42.restsecure.autoconfigure.components;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import nl._42.restsecure.autoconfigure.shared.test.AbstractApplicationContextTest;

import org.junit.Test;

public class AuthenticationControllerTest extends AbstractApplicationContextTest {

    @Test
    public void currentUser_shouldFail_whenNotLoggedIn() throws Exception {
        getWebClient()
            .perform(get("/authentication/current"))
            .andExpect(status().isUnauthorized());
    }

    @Test
    public void currentUser_shouldSucceed_whenLoggedIn() throws Exception {
        getWebClient(new CustomUser())
            .perform(get("/authentication/current"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("authorities[0]").value("ROLE_ADMIN"))
            .andExpect(jsonPath("username").value("username"));
    }

    @Test
    public void currentUser_shouldReturnCustomAuthenticationResult_withCustomAuthenticationResultProvider() throws Exception {
        getWebClient(ConfigWithCustomAuthenticationResultProvider.class, new CustomUser())
            .perform(get("/authentication/current"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("authorities[0]").value("ROLE_ADMIN"))
            .andExpect(jsonPath("username").value("customized"));
    }
    
    @Test
    public void authenticate_shouldSucceed_withCorrectCredentials_andNoopPasswordEncoder() throws Exception {
        getWebClient()
            .perform(post("/authentication")
                .content("{\"username\": \"custom\", \"password\": \"password\"}"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("authorities[0]").value("ROLE_ADMIN"))
            .andExpect(jsonPath("username").value("username"));
    }

    @Test
    public void authenticat_shouldFail_withCorrectCredentials_butBrcyptPasswordEncoder() throws Exception {
        getWebClient(ConfigWithUserDetailsService.class)
            .perform(post("/authentication")
                .content("{\"username\": \"custom\", \"password\": \"password\"}"))
            .andExpect(status().isUnauthorized());
    }
    
    @Test
    public void handshake_shouldReturnCsrfToken() throws Exception {
        getWebClient()
            .perform(get("/authentication/handshake"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("csrfToken").exists());
    }
}
