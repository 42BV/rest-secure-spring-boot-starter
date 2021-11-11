package nl._42.restsecure.autoconfigure.authentication.mfa;

public interface MfaValidationService {

    boolean verifyMfaCode(String secret, String code);
}
