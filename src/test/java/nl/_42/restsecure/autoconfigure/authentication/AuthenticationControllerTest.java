package nl._42.restsecure.autoconfigure.authentication;

import static nl._42.restsecure.autoconfigure.errorhandling.DefaultLoginAuthenticationExceptionHandler.SERVER_LOGIN_FAILED_ERROR;
import static nl._42.restsecure.autoconfigure.test.RememberMeServicesConfig.REMEMBER_ME_HEADER;
import static nl._42.restsecure.autoconfigure.test.RestAuthenticationSuccessHandlerConfig.AUTHENTICATION_SUCCESS_HEADER;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.anonymous;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
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
import nl._42.restsecure.autoconfigure.test.NoopPasswordEncoderConfig;
import nl._42.restsecure.autoconfigure.test.RememberMeServicesConfig;
import nl._42.restsecure.autoconfigure.test.RestAuthenticationSuccessHandlerConfig;

import org.junit.jupiter.api.Test;

class AuthenticationControllerTest extends AbstractApplicationContextTest {

    @Test
    void currentUser_shouldFail_whenNotLoggedIn() throws Exception {
        getWebClient(ActiveUserConfig.class)
                .perform(get("/authentication/current")
                        .with(anonymous()))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void currentUser_shouldSucceed_whenLoggedIn() throws Exception {
        getWebClient(ActiveUserConfig.class)
                .perform(get("/authentication/current"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("authorities[0]").value("ROLE_ADMIN"))
                .andExpect(jsonPath("username").value("username"));
    }

    @Test
    void currentUser_shouldSucceed_whenNotLoggedIn_andCustomWebSecurity() throws Exception {
        getWebClient(ActiveUserConfig.class, CustomWebSecurityAndHttpSecurityConfig.class)
                .perform(get("/authentication/current"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("authorities[0]").value("ROLE_ADMIN"))
                .andExpect(jsonPath("username").value("username"));
    }

    @Test
    void currentUser_shouldReturnCustomAuthenticationResult_withCustomAuthenticationResultProvider() throws Exception {
        getWebClient(AuthenticationResultProviderConfig.class)
                .perform(get("/authentication/current"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("authorities[0]").value("ROLE_ADMIN"))
                .andExpect(jsonPath("username").value("customized"));
    }

    @Test
    void authenticate_shouldSucceed_withCorrectCredentials() throws Exception {
        getWebClient(ActiveUserConfig.class, NoopPasswordEncoderConfig.class)
                .perform(post("/authentication")
                        .content("{\"username\": \"custom\", \"password\": \"password\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("authorities[0]").value("ROLE_ADMIN"))
                .andExpect(jsonPath("username").value("username"));
    }

    @Test
    void rememberMe_shouldSucceed_afterSuccessfulAuthentication() throws Exception {
        getWebClient(ActiveUserConfig.class, NoopPasswordEncoderConfig.class, RememberMeServicesConfig.class)
                .perform(post("/authentication")
                        .content("{\"username\": \"custom\", \"password\": \"password\", \"rememberMe\":true}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("authorities[0]").value("ROLE_ADMIN"))
                .andExpect(jsonPath("username").value("username"))
                .andExpect(header().string(REMEMBER_ME_HEADER, "success"));
    }

    @Test
    void rememberMe_shouldFail_afterFailedAutentication() throws Exception {
        getWebClient(ActiveUserConfig.class, NoopPasswordEncoderConfig.class, RememberMeServicesConfig.class)
                .perform(post("/authentication")
                        .content("{\"username\": \"custom\", \"password\": \"wrong\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("errorCode").value(SERVER_LOGIN_FAILED_ERROR))
                .andExpect(header().string(REMEMBER_ME_HEADER, "failed"));
    }

    @Test
    void successHanlder_shouldBeCalled_afterSuccessfulAuthentication() throws Exception {
        getWebClient(ActiveUserConfig.class, NoopPasswordEncoderConfig.class, RestAuthenticationSuccessHandlerConfig.class)
                .perform(post("/authentication")
                        .content("{\"username\": \"custom\", \"password\": \"password\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("authorities[0]").value("ROLE_ADMIN"))
                .andExpect(jsonPath("username").value("username"))
                .andExpect(header().string(AUTHENTICATION_SUCCESS_HEADER, "username"));
    }

    @Test
    void successHanlder_shouldNotBeCalled_afterFailedAuthentication() throws Exception {
        getWebClient(ActiveUserConfig.class, NoopPasswordEncoderConfig.class, RestAuthenticationSuccessHandlerConfig.class)
                .perform(post("/authentication")
                        .content("{\"username\": \"custom\", \"password\": \"wrong\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("errorCode").value(SERVER_LOGIN_FAILED_ERROR))
                .andExpect(header().doesNotExist(AUTHENTICATION_SUCCESS_HEADER));
    }

    @Test
    void authenticate_shouldFail_withCorrectCredentials_butBrcyptPasswordEncoder() throws Exception {
        getWebClient(ActiveUserConfig.class)
                .perform(post("/authentication")
                        .content("{\"username\": \"custom\", \"password\": \"password\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("errorCode").value(SERVER_LOGIN_FAILED_ERROR));
    }

    @Test
    void authenticate_shouldFail_withAccountExpired() throws Exception {
        getWebClient(AccountExpiredUserConfig.class, NoopPasswordEncoderConfig.class)
                .perform(post("/authentication")
                        .content("{\"username\": \"custom\", \"password\": \"password\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("errorCode").value(SERVER_LOGIN_FAILED_ERROR));
    }

    @Test
    void authenticate_shouldFail_withAccountLocked() throws Exception {
        getWebClient(AccountLockedUserConfig.class, NoopPasswordEncoderConfig.class)
                .perform(post("/authentication")
                        .content("{\"username\": \"custom\", \"password\": \"password\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("errorCode").value(SERVER_LOGIN_FAILED_ERROR));
    }

    @Test
    void authenticate_shouldFail_withCredentialsExpired() throws Exception {
        getWebClient(CredentialsExpiredUserConfig.class, NoopPasswordEncoderConfig.class)
                .perform(post("/authentication")
                        .content("{\"username\": \"custom\", \"password\": \"password\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("errorCode").value(SERVER_LOGIN_FAILED_ERROR));
    }

    @Test
    void authenticate_shouldFail_withAuthenticationExceptionInSubsequentFilter() throws Exception {
        getWebClient(ActiveUserConfig.class, NoopPasswordEncoderConfig.class, FailingTwoFactorAuthenticationFilterConfig.class)
                .perform(post("/authentication")
                        .content("{\"username\": \"custom\", \"password\": \"password\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("errorCode").value(SERVER_LOGIN_FAILED_ERROR));
    }
}
