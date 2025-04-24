package nl._42.restsecure.autoconfigure.authentication.mfa.email;

import java.time.Instant;
import java.util.Optional;

public interface EmailCodeRepository {
    void save(String email, String code, Instant expiresAt);
    Optional<EmailVerificationCode> findByEmail(String email);
    void deleteByEmail(String email);
}