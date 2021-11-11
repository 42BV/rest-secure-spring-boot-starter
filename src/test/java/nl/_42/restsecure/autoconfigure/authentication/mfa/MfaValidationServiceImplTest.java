package nl._42.restsecure.autoconfigure.authentication.mfa;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class MfaValidationServiceImplTest {

    @Nested
    class verifyMfaCode {

        @Test
        @DisplayName("should call codeVerifier to verify the MFA code")
        void shouldCallCodeVerifierToVerifyCode() {
            MfaValidationServiceImpl validationService = new MfaValidationServiceImpl((secret, code) -> secret.equals("i-am-here") && code.equals("123456"));

            assertTrue(validationService.verifyMfaCode("i-am-here", "123456"));
            assertFalse(validationService.verifyMfaCode("i-am-here", "123457"));
            assertFalse(validationService.verifyMfaCode("i-am-not-here", "123456"));
        }
    }
}
