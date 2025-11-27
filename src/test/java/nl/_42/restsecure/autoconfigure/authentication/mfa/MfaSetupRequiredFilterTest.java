package nl._42.restsecure.autoconfigure.authentication.mfa;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.springframework.http.HttpMethod.GET;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import nl._42.restsecure.autoconfigure.AbstractApplicationContextTest;
import nl._42.restsecure.autoconfigure.authentication.InMemoryUserDetailService;
import nl._42.restsecure.autoconfigure.test.MockMfaAuthenticationConfig;
import tools.jackson.databind.ObjectMapper;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.test.web.servlet.MockMvc;

class MfaSetupRequiredFilterTest extends AbstractApplicationContextTest {

    private MfaSetupRequiredFilter filter;
    private MockMvc webClient;

    private final UsernamePasswordAuthenticationToken authenticationWithValidMfaConfiguration = new MfaAuthenticationToken("user1", "*****", "123456");
    private final UsernamePasswordAuthenticationToken authenticationWithInvalidMfaConfiguration = new MfaAuthenticationToken("user2", "*****", "234567");

    {
        authenticationWithInvalidMfaConfiguration.setDetails(MfaAuthenticationProvider.DETAILS_MFA_SETUP_REQUIRED);
    }

    @BeforeEach
    void setup() {
        webClient = getWebClient(MockMfaAuthenticationConfig.class);
        filter = context.getBean(MfaSetupRequiredFilter.class);
        InMemoryUserDetailService userDetailService = (InMemoryUserDetailService) context.getBean(UserDetailsService.class);
        userDetailService.register(new UserWithMfa("user1", "*****", "mfa-secret", true, "admin"));
        userDetailService.register(new UserWithMfa("user2", "*****", null, true, "super-admin"));
        MockMfaValidationService mfaValidationService = (MockMfaValidationService) context.getBean(MfaValidationService.class);
        mfaValidationService.register("mfa-secret", "123456");
    }

    @Nested
    class afterPropertiesSet {

        @Test
        @DisplayName("should throw if ObjectMapper has not been set")
        void shouldThrowForMissingObjectMapper() {
            MfaSetupRequiredFilter mockFilter = new MfaSetupRequiredFilter();
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class, mockFilter::afterPropertiesSet);
            assertEquals("A ObjectMapper must be set", e.getMessage());

            mockFilter.setObjectMapper(new ObjectMapper());
            assertDoesNotThrow(mockFilter::afterPropertiesSet);
        }
    }

    @Nested
    class filter {
        @Test
        void shouldAllowRequest_whenExcludedByUrl() throws Exception {
            filter.getExcludedRequests().add(PathPatternRequestMatcher.withDefaults().matcher(GET, "/users/**"));

            webClient
                    .perform(get("/users/me")
                            .with(authentication(authenticationWithInvalidMfaConfiguration)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("username").value("user2"));
        }

        @Test
        void shouldAllowRequest_whenExcludedByLogicCheck() throws Exception {
            filter.getExclusionChecks().add((req, res) -> true);

            webClient
                    .perform(get("/users/me")
                            .with(authentication(authenticationWithInvalidMfaConfiguration)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("username").value("user2"));
        }

        @Test
        void shouldAllowRequest_withValidMfaConfiguration() throws Exception {
            webClient
                    .perform(get("/users/me")
                            .with(authentication(authenticationWithValidMfaConfiguration)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("username").value("user1"));
        }

        @Test
        void shouldDenyRequest_whenNotExcludedAndMfaConfigurationIsInvalid() throws Exception {
            webClient
                    .perform(get("/users/me")
                            .with(authentication(authenticationWithInvalidMfaConfiguration)))
                    .andExpect(status().isForbidden())
                    .andExpect(jsonPath("$.errorCode").value("SERVER.MFA_SETUP_REQUIRED_ERROR"));
        }
    }
}
