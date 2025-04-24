package nl._42.restsecure.autoconfigure.authentication.mfa.email;

public interface EmailCodeService {
    void generateAndSendCode(String email);
    boolean verifyCode(String email, String code);
}