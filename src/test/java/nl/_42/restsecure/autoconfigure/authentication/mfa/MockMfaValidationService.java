package nl._42.restsecure.autoconfigure.authentication.mfa;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public class MockMfaValidationService implements MfaValidationService {

    private Map<String, String> secretsAndCodes = new HashMap<>();

    public void register(String secret, String allowedCode) {
        secretsAndCodes.put(secret, allowedCode);
    }

    @Override
    public boolean verifyMfaCode(String secret, String code) {
        return code != null && Objects.equals(code, secretsAndCodes.get(secret));
    }
}
