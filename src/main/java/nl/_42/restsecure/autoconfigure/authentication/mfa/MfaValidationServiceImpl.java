package nl._42.restsecure.autoconfigure.authentication.mfa;

import dev.samstevens.totp.code.CodeVerifier;

/**
 * Service which contains logic to validate MFA tokens.
 */
public class MfaValidationServiceImpl implements MfaValidationService {

    private final CodeVerifier verifier;

    public MfaValidationServiceImpl(CodeVerifier verifier) {
        this.verifier = verifier;
    }

    /**
     * Validates if the given MFA code is valid right now.
     * @param secret Secret key of the user (e.g. from a database or credentials store)
     * @param code Given MFA code (usually a 6-digit key)
     * @return True if the given MFA code is valid. False if not.
     */
    public boolean verifyMfaCode(String secret, String code) {
        return verifier.isValidCode(secret, code);
    }
}
