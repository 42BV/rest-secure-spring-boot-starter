package nl._42.restsecure.autoconfigure.authentication.mfa;

/**
 * Service which contains logic to set up MFA authentication
 */
public interface MfaSetupService {

    /**
     * Generates a new MFA secret
     * The secret is to be stored in a secure way for the given user.
     * @return Secret key to generate a QR code and to validate MFA authentication codes.
     */
    String generateSecret();

    /**
     * Generates a new MFA QR code
     * @param secret Secret key of the user
     * @param label Label to show in the MFA app. This must be something related to the user (e.g. username, email address).
     * @return A base64-encoded DATA URI of the QR code. This can for example be used in a HTML img element.
     * @throws MfaException If the QR code cannot be generated.
     */
    String generateQrCode(String secret, String label) throws MfaException;
    
    /**
     * Sets up email-based MFA for a user
     * This method sends a verification code to the provided email address
     * to confirm that the email is valid before completing setup.
     * 
     * @param email The email address to use for MFA verification
     * @throws MfaException If email cannot be sent or if EmailCodeService is not configured
     */
    void setupEmailMfa(String email);
    
    /**
     * Verifies an email verification code during the setup process
     * 
     * @param email The email address that was used in setupEmailMfa
     * @param code The verification code that was received
     * @return true if the code is valid, false otherwise
     * @throws MfaException If EmailCodeService is not configured
     */
    default boolean verifyEmailMfaSetup(String email, String code) {
        throw new MfaException("Email verification not implemented");
    }
}
