package nl._42.restsecure.autoconfigure.authentication.mfa;

import static dev.samstevens.totp.util.Utils.getDataUriForImage;

import dev.samstevens.totp.exceptions.QrGenerationException;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.QrDataFactory;
import dev.samstevens.totp.qr.QrGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import nl._42.restsecure.autoconfigure.authentication.mfa.email.EmailCodeService;

/**
 * Service which contains logic to set up MFA authentication
 */
public class MfaSetupServiceImpl implements MfaSetupService {

    private final SecretGenerator secretGenerator;
    private final QrDataFactory qrDataFactory;
    private final QrGenerator qrGenerator;
    private final String issuer;
    private final EmailCodeService emailCodeService;

    public MfaSetupServiceImpl(SecretGenerator secretGenerator, QrDataFactory qrDataFactory, QrGenerator qrGenerator, String issuer) {
        this(secretGenerator, qrDataFactory, qrGenerator, issuer, null);
    }
    
    public MfaSetupServiceImpl(SecretGenerator secretGenerator, QrDataFactory qrDataFactory, QrGenerator qrGenerator, 
                             String issuer, EmailCodeService emailCodeService) {
        this.secretGenerator = secretGenerator;
        this.qrDataFactory = qrDataFactory;
        this.qrGenerator = qrGenerator;
        this.issuer = issuer;
        this.emailCodeService = emailCodeService;
    }

    /**
     * Generates a new MFA secret
     * The secret is to be stored in a secure way for the given user.
     * @return Secret key to generate a QR code and to validate MFA authentication codes.
     */
    public String generateSecret() {
        // Generates a new MFA secret
        return secretGenerator.generate();
    }

    /**
     * Generates a new MFA QR code
     * @param secret Secret key of the user
     * @param label Label to show in the MFA app. This must be something related to the user (e.g. username, email address).
     * @return A base64-encoded DATA URI of the QR code. This can for example be used in a HTML img element.
     * @throws MfaException If the QR code cannot be generated.
     */
    public String generateQrCode(String secret, String label) throws MfaException {
        if (label == null || label.equals("")) {
            throw new MfaException("Label cannot be blank!", null);
        }

        String labelWithIssuer;

        if (label.contains(issuer + ":")) {
            labelWithIssuer = label;
        } else {
            labelWithIssuer = String.format("%s:%s", issuer, label);
        }

        QrData data = qrDataFactory.newBuilder()
            .label(labelWithIssuer)
            .secret(secret)
            .issuer(issuer)
            .build();

        // Generate the QR code image data as a base64 string which
        // can be used in an <img> tag:
        try {
            return getDataUriForImage(
                    qrGenerator.generate(data),
                    qrGenerator.getImageMimeType()
            );
        } catch (QrGenerationException e) {
            throw new MfaException("Unable to generate QR code", e);
        }
    }
    
    @Override
    public void setupEmailMfa(String email) {
        if (emailCodeService == null) {
            throw new MfaException("EmailCodeService is not configured");
        }
        
        if (email == null || email.isEmpty()) {
            throw new MfaException("Email address cannot be empty");
        }
        
        // Send a test verification code to confirm the setup
        emailCodeService.generateAndSendCode(email);
    }
    
    @Override
    public boolean verifyEmailMfaSetup(String email, String code) {
        if (emailCodeService == null) {
            throw new MfaException("EmailCodeService is not configured");
        }
        
        if (email == null || email.isEmpty()) {
            throw new MfaException("Email address cannot be empty");
        }
        
        if (code == null || code.isEmpty()) {
            throw new MfaException("Verification code cannot be empty");
        }
        
        return emailCodeService.verifyCode(email, code);
    }
}
