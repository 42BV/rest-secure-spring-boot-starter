package nl._42.restsecure.autoconfigure.authentication.mfa;

import nl._42.restsecure.autoconfigure.authentication.RegisteredUser;

import org.springframework.security.core.AuthenticationException;

public interface MfaVerificationCheck {

    /**
     * Validates the MFA Authentication credentials for the given RegisteredUser.
     * If the credentials are valid, return true. The user will be logged in and no further checks will take place.
     * If this check is not applicable for this user, return false. The next check will then be tried.
     * If the credentials are not valid (but this check *is* applicable for this user), throw an AuthenticationException.
     * @param user User that is trying to log in.
     * @param authenticationToken Supplied authentication credentials (username, password, MFA token)
     * @return Returns true if this authentication is valid
     * @throws AuthenticationException if the supplied credentials are not valid
     */
    boolean validate(RegisteredUser user, MfaAuthenticationToken authenticationToken) throws AuthenticationException;
}
