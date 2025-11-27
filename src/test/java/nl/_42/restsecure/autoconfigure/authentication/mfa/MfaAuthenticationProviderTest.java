package nl._42.restsecure.autoconfigure.authentication.mfa;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;

import nl._42.restsecure.autoconfigure.authentication.InMemoryUserDetailService;
import nl._42.restsecure.autoconfigure.authentication.RegisteredUser;
import nl._42.restsecure.autoconfigure.authentication.User;
import nl._42.restsecure.autoconfigure.authentication.UserDetailsAdapter;
import nl._42.restsecure.autoconfigure.authentication.UserWithPassword;
import nl._42.restsecure.autoconfigure.errorhandling.DefaultLoginAuthenticationExceptionHandler;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;

class MfaAuthenticationProviderTest {

    @Nested
    class additionalAuthenticationChecks {

        private MfaAuthenticationProvider provider;
        private MfaAuthenticationProvider noUserDetailsAdapterProvider;
        private InMemoryUserDetailService inMemoryUserDetailService;
        private final UserDetailsService noUserDetailsAdapterUserDetailsService = username -> {
            if (Objects.equals(username, "username")) {
                return new org.springframework.security.core.userdetails.User(username, "password", Collections.emptyList());
            }
            throw new UsernameNotFoundException("User was not found");
        };
        private MockMfaValidationService mockMfaValidationService;

        @BeforeEach
        void setup() throws Exception {
            inMemoryUserDetailService = new InMemoryUserDetailService();
            mockMfaValidationService = new MockMfaValidationService();
            provider = new MfaAuthenticationProvider(inMemoryUserDetailService, mockMfaValidationService);
            provider.setPasswordEncoder(NoOpPasswordEncoder.getInstance());
            provider.afterPropertiesSet();
            noUserDetailsAdapterProvider = new MfaAuthenticationProvider(noUserDetailsAdapterUserDetailsService, mockMfaValidationService);
            noUserDetailsAdapterProvider.setPasswordEncoder(NoOpPasswordEncoder.getInstance());
            noUserDetailsAdapterProvider.afterPropertiesSet();
        }

        @Nested
        class afterPropertiesSet {

            @Test
            @DisplayName("should throw if userDetailsService or mfaValidationService have not been set")
            void shouldThrowForMissingDependencies() {
                IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> new MfaAuthenticationProvider(null, null));
                assertEquals("userDetailsService cannot be null", e.getMessage());

                MfaAuthenticationProvider mfaProvider = new MfaAuthenticationProvider(new InMemoryUserDetailService(), null);
                e = assertThrows(IllegalArgumentException.class, mfaProvider::doAfterPropertiesSet);
                assertEquals("A MfaValidationService must be set", e.getMessage());

                mfaProvider = new MfaAuthenticationProvider(new InMemoryUserDetailService(), new MockMfaValidationService());
                assertDoesNotThrow(mfaProvider::doAfterPropertiesSet);
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
                assertEquals(user, userDetailsAdapter.user());
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
                assertEquals(user, userDetailsAdapter.user());
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
                assertEquals(user, userDetailsAdapter.user());
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
                assertEquals(user, userDetailsAdapter.user());
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
                assertEquals(user, userDetailsAdapter.user());
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
            @DisplayName("should throw MfaRequiredException if the code is missing")
            void shouldThrowIfCodeMissing() {
                User user = new UserWithMfa("username", "password", "secret-key", false, "Hoi");
                inMemoryUserDetailService.register(user);
                mockMfaValidationService.register("secret-key", "123456");

                MfaAuthenticationToken nullToken = new MfaAuthenticationToken("username", "password", null);
                MfaRequiredException e = assertThrows(MfaRequiredException.class, () -> provider.authenticate(nullToken));
                assertEquals("SERVER.MFA_CODE_REQUIRED_ERROR", e.getMessage());

                MfaAuthenticationToken emptyStringToken = new MfaAuthenticationToken("username", "password", "");
                MfaRequiredException e2 = assertThrows(MfaRequiredException.class, () -> provider.authenticate(emptyStringToken));
                assertEquals("SERVER.MFA_CODE_REQUIRED_ERROR", e2.getMessage());
            }
        }

        @Nested
        class otherVerificationChecks {

            @Test
            @DisplayName("should throw if null is passed to setVerificationChecks")
            void shouldThrow_ForNullChecks() {
                MfaAuthenticationProvider mfaProvider = new MfaAuthenticationProvider(inMemoryUserDetailService, mockMfaValidationService);
                mfaProvider.setPasswordEncoder(NoOpPasswordEncoder.getInstance());
                mfaProvider.setVerificationChecks(null);
                IllegalArgumentException e = assertThrows(IllegalArgumentException.class, mfaProvider::doAfterPropertiesSet);
                assertEquals("At least one verification check must be provided", e.getMessage());

                mfaProvider.setVerificationChecks(new ArrayList<>());
                e = assertThrows(IllegalArgumentException.class, mfaProvider::doAfterPropertiesSet);
                assertEquals("At least one verification check must be provided", e.getMessage());

                mfaProvider.setVerificationChecks(List.of(new MfaTotpVerificationCheck(mockMfaValidationService)));
                assertDoesNotThrow(mfaProvider::doAfterPropertiesSet);
            }

            @Test
            @DisplayName("should only perform first check if it returns true")
            void shouldStop_ifCheckReturnsTrue() {
                AtomicBoolean firstCheckPerformed = new AtomicBoolean(false);
                AtomicBoolean secondCheckPerformed = new AtomicBoolean(false);

                RegisteredUser[] userFromCheck1 = new RegisteredUser[1];
                MfaAuthenticationToken[] authenticationTokenFromCheck1 = new MfaAuthenticationToken[1];

                MfaVerificationCheck check1 = (user, authenticationToken) -> {
                    firstCheckPerformed.compareAndSet(false, true);
                    userFromCheck1[0] = user;
                    authenticationTokenFromCheck1[0] = authenticationToken;
                    return true;
                };

                MfaVerificationCheck check2 = (user, authenticationToken) -> {
                    secondCheckPerformed.compareAndSet(false, true);
                    return false;
                };

                provider.setVerificationChecks(List.of(check1, check2));
                provider.doAfterPropertiesSet();

                User user = new UserWithMfa("username", "password", "secret-key", false, "Hoi");
                inMemoryUserDetailService.register(user);
                mockMfaValidationService.register("secret-key", "123456");

                MfaAuthenticationToken token = new MfaAuthenticationToken("username", "password",
                        "654321"); // This key should not be checked since the custom check succeeds.
                Authentication authentication = provider.authenticate(token);

                assertTrue(authentication.isAuthenticated());

                assertTrue(firstCheckPerformed.get());
                assertFalse(secondCheckPerformed.get());

                assertEquals(user, userFromCheck1[0]);
                assertEquals(token, authenticationTokenFromCheck1[0]);
            }

            @Test
            @DisplayName("should perform other checks and then MfaTotpVerificationCheck if they return false")
            void shouldContinue_ifCheckReturnsFalse() {
                AtomicBoolean firstCheckPerformed = new AtomicBoolean(false);
                AtomicBoolean secondCheckPerformed = new AtomicBoolean(false);

                RegisteredUser[] userFromCheck1 = new RegisteredUser[1];
                MfaAuthenticationToken[] authenticationTokenFromCheck1 = new MfaAuthenticationToken[1];

                RegisteredUser[] userFromCheck2 = new RegisteredUser[1];
                MfaAuthenticationToken[] authenticationTokenFromCheck2 = new MfaAuthenticationToken[1];

                MfaVerificationCheck check1 = (user, authenticationToken) -> {
                    firstCheckPerformed.compareAndSet(false, true);
                    userFromCheck1[0] = user;
                    authenticationTokenFromCheck1[0] = authenticationToken;
                    return false;
                };

                MfaVerificationCheck check2 = (user, authenticationToken) -> {
                    secondCheckPerformed.compareAndSet(false, true);
                    userFromCheck2[0] = user;
                    authenticationTokenFromCheck2[0] = authenticationToken;
                    return false;
                };

                provider.setVerificationChecks(List.of(check1, check2));
                provider.doAfterPropertiesSet();

                User user = new UserWithMfa("username", "password", "secret-key", false, "Hoi");
                inMemoryUserDetailService.register(user);
                mockMfaValidationService.register("secret-key", "123456");

                MfaAuthenticationToken token = new MfaAuthenticationToken("username", "password", "123456");
                Authentication authentication = provider.authenticate(token);

                assertTrue(authentication.isAuthenticated());

                assertTrue(firstCheckPerformed.get());
                assertTrue(secondCheckPerformed.get());

                assertEquals(user, userFromCheck1[0]);
                assertEquals(token, authenticationTokenFromCheck1[0]);

                assertEquals(user, userFromCheck2[0]);
                assertEquals(token, authenticationTokenFromCheck2[0]);

                // Ensure the mfa key is actually checked by trying again with a wrong key - this should throw exception
                MfaAuthenticationToken wrongKeyToken = new MfaAuthenticationToken("username", "password", "654321");
                AuthenticationException e = assertThrows(AuthenticationException.class, () -> provider.authenticate(wrongKeyToken));
                assertEquals(DefaultLoginAuthenticationExceptionHandler.SERVER_LOGIN_FAILED_ERROR, e.getMessage());
            }

            @Test
            @DisplayName("should put the TotpVerificationCheck in the custom position if it is explicitly passed to setVerificationChecks")
            void shouldInsertTotpCheckAtGivenPosition() {
                AtomicBoolean checkPerformed = new AtomicBoolean(false);

                RegisteredUser[] userFromCheck = new RegisteredUser[1];
                MfaAuthenticationToken[] authenticationTokenFromCheck = new MfaAuthenticationToken[1];

                MfaVerificationCheck check = (user, authenticationToken) -> {
                    checkPerformed.compareAndSet(false, true);
                    userFromCheck[0] = user;
                    authenticationTokenFromCheck[0] = authenticationToken;
                    return false;
                };

                // We create a custom instance of MfaTotpVerificationCheck to allow skipping a certain key.
                provider.setVerificationChecks(List.of(new CustomTotpVerificationCheck(mockMfaValidationService), check));
                provider.doAfterPropertiesSet();

                User user = new UserWithMfa("username", "password", "secret-key", false, "Hoi");
                inMemoryUserDetailService.register(user);
                mockMfaValidationService.register("secret-key", "123456");

                MfaAuthenticationToken token = new MfaAuthenticationToken("username", "password", "123456");
                Authentication authentication = provider.authenticate(token);

                assertTrue(authentication.isAuthenticated());
                assertFalse(checkPerformed.get()); // Mfa key was valid, the second check is not needed.

                // Now, authenticate with a skipped key hardcoded in a custom MfaTotpVerificationCheck (unlikely in practice, but test nonetheless).
                // Since none of the checks have been applicable to this user, an IllegalStateException will be thrown (since applications must at least perform one check)
                MfaAuthenticationToken tokenInvalid = new MfaAuthenticationToken("username", "password", "654321");
                IllegalStateException e = assertThrows(IllegalStateException.class, () -> provider.authenticate(tokenInvalid));

                assertEquals(
                        "At least one verification check must either have succeeded or thrown an AuthenticationException. Check the verifications passed to .setVerificationChecks() for any unmatched scenarios.",
                        e.getMessage());
                assertTrue(checkPerformed.get());
                assertEquals(user, userFromCheck[0]);
                assertEquals(tokenInvalid, authenticationTokenFromCheck[0]);
            }

            @Test
            @DisplayName("should not perform other checks if first check throws")
            void shouldStop_ifCheckThrows() {
                AtomicBoolean secondCheckPerformed = new AtomicBoolean(false);

                MfaVerificationCheck check1 = (user, authenticationToken) -> {
                    throw new BadCredentialsException("Unable to sign in this user");
                };

                MfaVerificationCheck check2 = (user, authenticationToken) -> {
                    secondCheckPerformed.compareAndSet(false, true);
                    return false;
                };

                provider.setVerificationChecks(List.of(check1, check2));
                provider.doAfterPropertiesSet();

                User user = new UserWithMfa("username", "password", "secret-key", false, "Hoi");
                inMemoryUserDetailService.register(user);
                mockMfaValidationService.register("secret-key", "123456");

                MfaAuthenticationToken token = new MfaAuthenticationToken("username", "password", "123456");
                BadCredentialsException e = assertThrows(BadCredentialsException.class, () -> provider.authenticate(token));
                assertEquals("Unable to sign in this user", e.getMessage());

                assertFalse(secondCheckPerformed.get());
            }

            static class CustomTotpVerificationCheck extends MfaTotpVerificationCheck {

                public CustomTotpVerificationCheck(MfaValidationService mfaValidationService) {
                    super(mfaValidationService);
                }

                @Override
                public boolean validate(RegisteredUser user, MfaAuthenticationToken authenticationToken) throws AuthenticationException {
                    if (authenticationToken.getVerificationCode() != null && authenticationToken.getVerificationCode().equals("654321")) {
                        return false;
                    }
                    return super.validate(user, authenticationToken);
                }
            }
        }

        @Nested
        class otherUserTypes {

            @Test
            @DisplayName("should not perform additional authentication checks if user is not of type UserDetailsAdapter")
            void shouldDoNothingForOtherUsers() {

                MfaAuthenticationToken token = new MfaAuthenticationToken("username", "password", "123456");
                Authentication authentication = noUserDetailsAdapterProvider.authenticate(token);

                assertTrue(authentication.isAuthenticated());
                assertTrue(authentication instanceof UsernamePasswordAuthenticationToken);

                MfaAuthenticationToken wrongToken = new MfaAuthenticationToken("username", "passwrod", "123456");
                assertThrows(BadCredentialsException.class, () -> provider.authenticate(wrongToken));
            }
        }
    }
}
