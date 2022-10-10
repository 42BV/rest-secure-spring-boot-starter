package nl._42.restsecure.autoconfigure.authentication.mfa;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class MfaAuthenticationTokenTest {

    @Test
    void getVerificationCode() {
        assertEquals("424242", new MfaAuthenticationToken("user", "secret", "424242").getVerificationCode());
        assertEquals("242424", new MfaAuthenticationToken("user", "secret", "242424").getVerificationCode());
    }
}
