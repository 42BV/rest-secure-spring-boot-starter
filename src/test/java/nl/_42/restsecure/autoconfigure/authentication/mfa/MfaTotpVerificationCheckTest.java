package nl._42.restsecure.autoconfigure.authentication.mfa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import nl._42.restsecure.autoconfigure.authentication.UserDetailsAdapter;
import nl._42.restsecure.autoconfigure.errorhandling.DefaultLoginAuthenticationExceptionHandler;

import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.BadCredentialsException;

class MfaTotpVerificationCheckTest {

    @Test
    void validate() {
        MfaValidationService mfaValidationService = (secret, code) -> secret != null && secret.equals("secret-key") && code != null && code.equals("123456");

        MfaTotpVerificationCheck check = new MfaTotpVerificationCheck(mfaValidationService);

        UserWithMfa userValid = new UserWithMfa("user", "pw", "secret-key", true, "testRole");
        UserWithMfa userInvalid = new UserWithMfa("user", "pw", "stolen-key", true, "testRole");

        MfaAuthenticationToken tokenValid = new MfaAuthenticationToken(new UserDetailsAdapter<>(userValid), "*****", "123456");
        MfaAuthenticationToken tokenInvalidCode = new MfaAuthenticationToken(new UserDetailsAdapter<>(userValid), "*****", "654321");

        assertTrue(check.validate(userValid, tokenValid));

        BadCredentialsException e1 = assertThrows(BadCredentialsException.class, () -> check.validate(userValid, tokenInvalidCode));
        BadCredentialsException e2 = assertThrows(BadCredentialsException.class, () -> check.validate(userInvalid, tokenValid));
        BadCredentialsException e3 = assertThrows(BadCredentialsException.class, () -> check.validate(userInvalid, tokenInvalidCode));

        assertEquals(DefaultLoginAuthenticationExceptionHandler.SERVER_LOGIN_FAILED_ERROR, e1.getMessage());
        assertEquals(DefaultLoginAuthenticationExceptionHandler.SERVER_LOGIN_FAILED_ERROR, e2.getMessage());
        assertEquals(DefaultLoginAuthenticationExceptionHandler.SERVER_LOGIN_FAILED_ERROR, e3.getMessage());
    }
}
