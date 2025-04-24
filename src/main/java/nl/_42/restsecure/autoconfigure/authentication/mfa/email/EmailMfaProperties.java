package nl._42.restsecure.autoconfigure.authentication.mfa.email;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Getter
@Setter
@ConfigurationProperties(prefix = "rest-secure.mfa.email")
public class EmailMfaProperties {
    private boolean enabled = false;
    private int codeLength = 6;
    private int codeValiditySeconds = 300;
    private String emailSubject = "Your verification code";
    private String emailFrom;
    private String emailTemplate = "Your verification code is: {code}";
}