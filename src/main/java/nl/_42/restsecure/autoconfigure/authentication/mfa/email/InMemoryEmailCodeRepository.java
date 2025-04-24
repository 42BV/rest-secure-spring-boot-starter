package nl._42.restsecure.autoconfigure.authentication.mfa.email;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

public class InMemoryEmailCodeRepository implements EmailCodeRepository {
    private final Map<String, EmailVerificationCode> codes = new ConcurrentHashMap<>();

    @Override
    public void save(String email, String code, Instant expiresAt) {
        codes.put(email, new EmailVerificationCode(email, code, expiresAt));
    }

    @Override
    public Optional<EmailVerificationCode> findByEmail(String email) {
        EmailVerificationCode code = codes.get(email);
        if (code != null && code.isExpired()) {
            codes.remove(email);
            return Optional.empty();
        }
        return Optional.ofNullable(code);
    }

    @Override
    public void deleteByEmail(String email) {
        codes.remove(email);
    }
}