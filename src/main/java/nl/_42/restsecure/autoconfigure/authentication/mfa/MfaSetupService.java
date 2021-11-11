package nl._42.restsecure.autoconfigure.authentication.mfa;

public interface MfaSetupService {

    String generateSecret();

    String generateQrCode(String secret, String label) throws MfaException;
}
