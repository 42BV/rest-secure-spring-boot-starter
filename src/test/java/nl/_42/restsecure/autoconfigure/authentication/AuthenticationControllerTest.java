package nl._42.restsecure.autoconfigure.authentication;

import static nl._42.restsecure.autoconfigure.errorhandling.DefaultLoginAuthenticationExceptionHandler.SERVER_LOGIN_FAILED_ERROR;
import static nl._42.restsecure.autoconfigure.test.RememberMeServicesConfig.REMEMBER_ME_HEADER;
import static nl._42.restsecure.autoconfigure.test.RestAuthenticationSuccessHandlerConfig.AUTHENTICATION_SUCCESS_HEADER;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.anonymous;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import jakarta.servlet.http.HttpSession;
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
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MockMvc;

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
                        .with(anonymous())
                        .content("{\"username\": \"custom\", \"password\": \"password\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("authorities[0]").value("ROLE_ADMIN"))
                .andExpect(jsonPath("username").value("username"));
    }

    @Test
    void authenticate_shouldChangeSessionId_toPreventSessionFixationAttack() throws Exception {
        MockMvc client = getWebClientWithoutUser(ActiveUserConfig.class, NoopPasswordEncoderConfig.class);

        HttpSession session = client.perform(get("/test/unguarded"))
            .andExpect(status().isOk())
            .andReturn().getRequest().getSession();
        // a new session should be created on first anonymous endpoint call
        String initialSessionId = session.getId();
        assertThat(initialSessionId).isNotBlank();
        assertThat(session.isNew()).isTrue();

        session = client.perform(post("/authentication")
                .session((MockHttpSession) session)
                .content("{\"username\": \"custom\", \"password\": \"password\"}"))
                .andExpect(status().isOk())
                .andReturn().getRequest().getSession();
        // session will be reused, but the sessionId must have been changed after login
        String loggedInSessionId = session.getId();
        assertThat(loggedInSessionId).isNotBlank().isNotEqualTo(initialSessionId);
        assertThat(session.isNew()).isFalse();

        session = client.perform(get("/users/me")
                .session((MockHttpSession) session))
                .andExpect(status().isOk())
                .andReturn().getRequest().getSession();
        // the session and its id remains unchanged during subsequent requests
        String unchangedSessionId = session.getId();
        assertThat(unchangedSessionId).isNotBlank().isEqualTo(loggedInSessionId);
        assertThat(session.isNew()).isFalse();

        session = client.perform(delete("/authentication")
                .session((MockHttpSession) session))
                .andExpect(status().isOk())
                .andReturn().getRequest().getSession();
        // a new session will be created after logout
        String loggoutSessionId = session.getId();
        assertThat(loggoutSessionId).isNotBlank().isNotEqualTo(loggedInSessionId);
        assertThat(session.isNew()).isTrue();
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
