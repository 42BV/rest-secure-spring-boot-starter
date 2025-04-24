package nl._42.restsecure.autoconfigure.authentication.mfa.email;

import java.time.Instant;
import java.util.Objects;

public class EmailVerificationCode {
    private final String email;
    private final String code;
    private final Instant expiresAt;

    public EmailVerificationCode(String email, String code, Instant expiresAt) {
        this.email = email;
        this.code = code;
        this.expiresAt = expiresAt;
    }

    public String getEmail() {
        return email;
    }

    public String getCode() {
        return code;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public boolean isExpired() {
        return Instant.now().isAfter(expiresAt);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        EmailVerificationCode that = (EmailVerificationCode) o;
        return Objects.equals(email, that.email);
    }

    @Override
    public int hashCode() {
        return Objects.hash(email);
    }
}