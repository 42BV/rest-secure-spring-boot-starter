package nl._42.restsecure.autoconfigure.authentication.mfa;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Collections;
import java.util.Objects;

import nl._42.restsecure.autoconfigure.authentication.InMemoryUserDetailService;
import nl._42.restsecure.autoconfigure.authentication.User;
import nl._42.restsecure.autoconfigure.authentication.UserDetailsAdapter;
import nl._42.restsecure.autoconfigure.authentication.UserWithPassword;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;

class MfaAuthenticationProviderTest {

    @Nested
    class additionalAuthenticationChecks {

        private MfaAuthenticationProvider provider;
        private InMemoryUserDetailService inMemoryUserDetailService;
        private final UserDetailsService noUserDetailsAdapterUserDetailsService = username -> {
            if (Objects.equals(username, "username")) {
                return new org.springframework.security.core.userdetails.User(username, "password", Collections.emptyList());
            }
            throw new UsernameNotFoundException("User was not found");
        };
        private MockMfaValidationService mockMfaValidationService;

        @BeforeEach
        void setup() {
            inMemoryUserDetailService = new InMemoryUserDetailService();
            mockMfaValidationService = new MockMfaValidationService();
            provider = new MfaAuthenticationProvider();
            provider.setUserDetailsService(inMemoryUserDetailService);
            provider.setPasswordEncoder(NoOpPasswordEncoder.getInstance());
            provider.setMfaValidationService(mockMfaValidationService);
        }

        @Nested
        class afterPropertiesSet {

            @Test
            @DisplayName("should throw if userDetailsService or mfaValidationService have not been set")
            void shouldThrowForMissingDependencies() {
                MfaAuthenticationProvider provider = new MfaAuthenticationProvider();
                IllegalArgumentException e = assertThrows(IllegalArgumentException.class, provider::doAfterPropertiesSet);
                assertEquals("A UserDetailsService must be set", e.getMessage());

                provider.setUserDetailsService(new InMemoryUserDetailService());
                e = assertThrows(IllegalArgumentException.class, provider::doAfterPropertiesSet);
                assertEquals("A MfaValidationService must be set", e.getMessage());

                provider.setMfaValidationService(new MockMfaValidationService());
                assertDoesNotThrow(provider::doAfterPropertiesSet);
            }
        }

        @Nested
        class mfaDisabledNonMandatory {

            @Test
            @DisplayName("should login with just username/password")
            void shouldLoginWithUsernameAndPassword() {
                User user = new UserWithPassword("username", "password", "Hoi");
                inMemoryUserDetailService.register(user);

                MfaAuthenticationToken token = new MfaAuthenticationToken("username", "password", null);
                Authentication authentication = provider.authenticate(token);

                assertTrue(authentication.isAuthenticated());
                assertTrue(authentication instanceof UsernamePasswordAuthenticationToken);
                UserDetailsAdapter<UserWithPassword> userDetailsAdapter = (UserDetailsAdapter<UserWithPassword>) authentication.getPrincipal();
                assertEquals(user, userDetailsAdapter.getUser());
                assertNull(authentication.getDetails());
            }

            @Test
            @DisplayName("should throw bad credentials exception for invalid username or password")
            void shouldThrowForBadCredentials() {
                User user = new UserWithPassword("username", "password", "Hoi");
                inMemoryUserDetailService.register(user);

                MfaAuthenticationToken tokenUsernameWrong = new MfaAuthenticationToken("someone-else", "password", null);
                MfaAuthenticationToken tokenPasswordWrong = new MfaAuthenticationToken("username", "wont-say-this", null);
                BadCredentialsException e1 = assertThrows(BadCredentialsException.class, () -> provider.authenticate(tokenUsernameWrong));
                BadCredentialsException e2 = assertThrows(BadCredentialsException.class, () -> provider.authenticate(tokenPasswordWrong));
                assertEquals("Bad credentials", e1.getMessage());
                assertEquals("Bad credentials", e2.getMessage());
            }
        }

        @Nested
        class mfaDisabledMandatory {
            @Test
            @DisplayName("should add 'mfa setup required' details for user without mfa whilst mfa is mandatory - no MFA code provided")
            void shouldIndicateSetupRequiredWithoutMfaCode() {
                User user = new UserWithMfa("username", "password", null, true, "Hoi");
                inMemoryUserDetailService.register(user);

                MfaAuthenticationToken token = new MfaAuthenticationToken("username", "password", null);
                Authentication authentication = provider.authenticate(token);

                assertTrue(authentication.isAuthenticated());
                assertTrue(authentication instanceof UsernamePasswordAuthenticationToken);
                UserDetailsAdapter<UserWithPassword> userDetailsAdapter = (UserDetailsAdapter<UserWithPassword>) authentication.getPrincipal();
                assertEquals(user, userDetailsAdapter.getUser());
                assertEquals(MfaAuthenticationProvider.DETAILS_MFA_SETUP_REQUIRED, authentication.getDetails());
            }

            @Test
            @DisplayName("should add 'mfa setup required' details for user without mfa whilst mfa is mandatory - MFA code provided")
            void shouldIndicateSetupRequiredWithMfaCode() {
                User user = new UserWithMfa("username", "password", null, true, "Hoi");
                inMemoryUserDetailService.register(user);

                MfaAuthenticationToken token = new MfaAuthenticationToken("username", "password", "123456");
                Authentication authentication = provider.authenticate(token);

                assertTrue(authentication.isAuthenticated());
                assertTrue(authentication instanceof UsernamePasswordAuthenticationToken);
                UserDetailsAdapter<UserWithPassword> userDetailsAdapter = (UserDetailsAdapter<UserWithPassword>) authentication.getPrincipal();
                assertEquals(user, userDetailsAdapter.getUser());
                assertEquals(MfaAuthenticationProvider.DETAILS_MFA_SETUP_REQUIRED, authentication.getDetails());
            }
        }

        @Nested
        class mfaEnabled {

            @Test
            @DisplayName("should authenticate if the code is valid - mfa enabled & mandatory")
            void shouldAuthenticateValidCode_mfaMandatory() {
                User user = new UserWithMfa("username", "password", "secret-key", true, "Hoi");
                inMemoryUserDetailService.register(user);
                mockMfaValidationService.register("secret-key", "123456");

                MfaAuthenticationToken token = new MfaAuthenticationToken("username", "password", "123456");
                Authentication authentication = provider.authenticate(token);

                assertTrue(authentication.isAuthenticated());
                assertTrue(authentication instanceof UsernamePasswordAuthenticationToken);
                UserDetailsAdapter<UserWithPassword> userDetailsAdapter = (UserDetailsAdapter<UserWithPassword>) authentication.getPrincipal();
                assertEquals(user, userDetailsAdapter.getUser());
                assertNull(authentication.getDetails());
            }

            @Test
            @DisplayName("should authenticate if the code is valid - mfa enabled & not mandatory")
            void shouldAuthenticateValidCode_mfaNotMandatory() {
                User user = new UserWithMfa("username", "password", "secret-key", false, "Hoi");
                inMemoryUserDetailService.register(user);
                mockMfaValidationService.register("secret-key", "123456");

                MfaAuthenticationToken token = new MfaAuthenticationToken("username", "password", "123456");
                Authentication authentication = provider.authenticate(token);

                assertTrue(authentication.isAuthenticated());
                assertTrue(authentication instanceof UsernamePasswordAuthenticationToken);
                UserDetailsAdapter<UserWithPassword> userDetailsAdapter = (UserDetailsAdapter<UserWithPassword>) authentication.getPrincipal();
                assertEquals(user, userDetailsAdapter.getUser());
                assertNull(authentication.getDetails());
            }

            @Test
            @DisplayName("should throw BadCredentialsException if the code is invalid")
            void shouldThrowIfCodeInvalid() {
                User user = new UserWithMfa("username", "password", "secret-key", false, "Hoi");
                inMemoryUserDetailService.register(user);
                mockMfaValidationService.register("secret-key", "123456");

                MfaAuthenticationToken token = new MfaAuthenticationToken("username", "password", "234567");
                BadCredentialsException e = assertThrows(BadCredentialsException.class, () -> provider.authenticate(token));
                assertEquals("SERVER.LOGIN_FAILED_ERROR", e.getMessage());
            }

            @Test
            @DisplayName("should throw InsufficientAuthenticationException if the code is missing")
            void shouldThrowIfCodeMissing() {
                User user = new UserWithMfa("username", "password", "secret-key", false, "Hoi");
                inMemoryUserDetailService.register(user);
                mockMfaValidationService.register("secret-key", "123456");

                MfaAuthenticationToken nullToken = new MfaAuthenticationToken("username", "password", null);
                InsufficientAuthenticationException e = assertThrows(InsufficientAuthenticationException.class, () -> provider.authenticate(nullToken));
                assertEquals("SERVER.MFA_CODE_REQUIRED_ERROR", e.getMessage());

                MfaAuthenticationToken emptyStringToken = new MfaAuthenticationToken("username", "password", "");
                InsufficientAuthenticationException e2 = assertThrows(InsufficientAuthenticationException.class, () -> provider.authenticate(emptyStringToken));
                assertEquals("SERVER.MFA_CODE_REQUIRED_ERROR", e2.getMessage());
            }
        }

        @Nested
        class otherUserTypes {

            @Test
            @DisplayName("should not perform additional authentication checks if user is not of type UserDetailsAdapter")
            void shouldDoNothingForOtherUsers() {
                provider.setUserDetailsService(noUserDetailsAdapterUserDetailsService);

                MfaAuthenticationToken token = new MfaAuthenticationToken("username", "password", "123456");
                Authentication authentication = provider.authenticate(token);

                assertTrue(authentication.isAuthenticated());
                assertTrue(authentication instanceof UsernamePasswordAuthenticationToken);

                MfaAuthenticationToken wrongToken = new MfaAuthenticationToken("username", "passwrod", "123456");
                assertThrows(BadCredentialsException.class, () -> provider.authenticate(wrongToken));
            }
        }
    }

    @Test
    void supports() {
        assertTrue(new MfaAuthenticationProvider().supports(MfaAuthenticationToken.class));
        assertFalse(new MfaAuthenticationProvider().supports(UsernamePasswordAuthenticationToken.class));
    }
}
