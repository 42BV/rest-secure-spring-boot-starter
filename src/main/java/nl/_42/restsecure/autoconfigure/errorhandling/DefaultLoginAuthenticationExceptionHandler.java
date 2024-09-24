package nl._42.restsecure.autoconfigure.errorhandling;

import static nl._42.restsecure.autoconfigure.authentication.mfa.MfaAuthenticationProvider.SERVER_MFA_CODE_REQUIRED_ERROR;
import static org.springframework.http.HttpStatus.UNAUTHORIZED;

import java.io.IOException;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import lombok.RequiredArgsConstructor;

import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.AuthenticationException;

@RequiredArgsConstructor
public class DefaultLoginAuthenticationExceptionHandler implements LoginAuthenticationExceptionHandler{

    public static final String SERVER_LOGIN_FAILED_ERROR = "SERVER.LOGIN_FAILED_ERROR";
    private final GenericErrorHandler errorHandler;

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException {
        // If the MFA code is needed but not provided, indicate this so the client can trigger the MFA login procedure.
        if (exception instanceof InsufficientAuthenticationException
                && exception.getMessage().equals(SERVER_MFA_CODE_REQUIRED_ERROR)) {
            errorHandler.respond(response, UNAUTHORIZED, SERVER_MFA_CODE_REQUIRED_ERROR);
        } else {
            errorHandler.respond(response, UNAUTHORIZED, SERVER_LOGIN_FAILED_ERROR);
        }
    }
}
