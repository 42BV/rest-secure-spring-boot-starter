package nl._42.restsecure.autoconfigure.authentication;

import static nl._42.restsecure.autoconfigure.RestAuthenticationFilter.SERVER_LOGIN_FAILED_ERROR;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.anonymous;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import nl._42.restsecure.autoconfigure.AbstractApplicationContextTest;
import nl._42.restsecure.autoconfigure.test.AccountExpiredUserConfig;
import nl._42.restsecure.autoconfigure.test.AccountLockedUserConfig;
import nl._42.restsecure.autoconfigure.test.ActiveUserConfig;
import nl._42.restsecure.autoconfigure.test.AuthenticationResultProviderConfig;
import nl._42.restsecure.autoconfigure.test.CredentialsExpiredUserConfig;
import nl._42.restsecure.autoconfigure.test.CustomWebSecurityAndHttpSecurityConfig;
import nl._42.restsecure.autoconfigure.test.FailingTwoFactorAuthenticationFilterConfig;
import nl._42.restsecure.autoconfigure.test.InMemoryCrowdConfig;
import nl._42.restsecure.autoconfigure.test.MockedCrowdAuthenticationProviderConfig;
import nl._42.restsecure.autoconfigure.test.NoopPasswordEncoderConfig;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.test.context.support.WithMockUser;

public class AuthenticationControllerTest extends AbstractApplicationContextTest {

    @Test
    public void currentUser_shouldFail_whenNotLoggedIn() throws Exception {
        getWebClient(ActiveUserConfig.class)
            .perform(get("/authentication/current")
                .with(anonymous()))
            .andExpect(status().isUnauthorized());
    }

    @Test
    @WithUser("T(nl._42.restsecure.autoconfigure.test.AbstractUserDetailsServiceConfig.RegisteredUserBuilder).user().build()")
    public void currentUser_shouldSucceed_whenLoggedIn() throws Exception {
        getWebClient(ActiveUserConfig.class)
            .perform(get("/authentication/current"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("authorities[0]").value("ROLE_ADMIN"))
            .andExpect(jsonPath("username").value("username"));
    }

    @Test
    @WithUser("T(nl._42.restsecure.autoconfigure.test.AbstractUserDetailsServiceConfig.RegisteredUserBuilder).user().build()")
    public void currentUser_shouldSucceed_whenNotLoggedIn_andCustomWebSecurity() throws Exception {
        getWebClient(ActiveUserConfig.class, CustomWebSecurityAndHttpSecurityConfig.class)
            .perform(get("/authentication/current"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("authorities[0]").value("ROLE_ADMIN"))
            .andExpect(jsonPath("username").value("username"));
    }

    @Test
    @WithUser("T(nl._42.restsecure.autoconfigure.test.AbstractUserDetailsServiceConfig.RegisteredUserBuilder).user().build()")
    public void currentUser_shouldReturnCustomAuthenticationResult_withCustomAuthenticationResultProvider() throws Exception {
        getWebClient(AuthenticationResultProviderConfig.class)
            .perform(get("/authentication/current"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("authorities[0]").value("ROLE_ADMIN"))
            .andExpect(jsonPath("username").value("customized"));
    }

    @Test
    public void authenticate_shouldSucceed_withCorrectCredentials() throws Exception {
        getWebClient(ActiveUserConfig.class, NoopPasswordEncoderConfig.class)
            .perform(post("/authentication")
                .content("{\"username\": \"custom\", \"password\": \"password\"}"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("authorities[0]").value("ROLE_ADMIN"))
            .andExpect(jsonPath("username").value("username"));
    }

    @Test
    public void authenticate_shouldFail_withCorrectCredentials_butBrcyptPasswordEncoder() throws Exception {
        getWebClient(ActiveUserConfig.class)
            .perform(post("/authentication")
                .content("{\"username\": \"custom\", \"password\": \"password\"}"))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("errorCode").value(SERVER_LOGIN_FAILED_ERROR));
    }
    
    @Test
    public void authenticate_shouldFail_withAccountExpired() throws Exception {
        getWebClient(AccountExpiredUserConfig.class, NoopPasswordEncoderConfig.class)
            .perform(post("/authentication")
                .content("{\"username\": \"custom\", \"password\": \"password\"}"))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("errorCode").value(SERVER_LOGIN_FAILED_ERROR));
    }
    
    @Test
    public void authenticate_shouldFail_withAccountLocked() throws Exception {
        getWebClient(AccountLockedUserConfig.class, NoopPasswordEncoderConfig.class)
            .perform(post("/authentication")
                .content("{\"username\": \"custom\", \"password\": \"password\"}"))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("errorCode").value(SERVER_LOGIN_FAILED_ERROR));
    }
    
    @Test
    public void authenticate_shouldFail_withCredentialsExpired() throws Exception {
        getWebClient(CredentialsExpiredUserConfig.class, NoopPasswordEncoderConfig.class)
            .perform(post("/authentication")
                .content("{\"username\": \"custom\", \"password\": \"password\"}"))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("errorCode").value(SERVER_LOGIN_FAILED_ERROR));
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
    public void authenticate_shouldFail_withIncorrectCredentials() throws Exception {
        getWebClient(InMemoryCrowdConfig.class, NoopPasswordEncoderConfig.class)
            .perform(post("/authentication")
                .content("{\"username\": \"unknownUser\", \"password\": \"secret\"}"))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("errorCode").value(SERVER_LOGIN_FAILED_ERROR));
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
    public void authenticate_shouldFail_withAuthenticationExceptionInSubsequentFilter() throws Exception {
        getWebClient(ActiveUserConfig.class, NoopPasswordEncoderConfig.class, FailingTwoFactorAuthenticationFilterConfig.class)
                .perform(post("/authentication")
                        .content("{\"username\": \"custom\", \"password\": \"password\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("errorCode").value(SERVER_LOGIN_FAILED_ERROR));
    }
}
