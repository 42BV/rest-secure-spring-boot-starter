package nl._42.restsecure.autoconfigure.errorhandling;

import static org.springframework.http.HttpStatus.UNAUTHORIZED;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.AuthenticationException;

public class DefaultLoginAuthenticationExceptionHandler implements LoginAuthenticationExceptionHandler{

    public static final String SERVER_LOGIN_FAILED_ERROR = "SERVER.LOGIN_FAILED_ERROR";

    private final GenericErrorHandler errorHandler;

    public DefaultLoginAuthenticationExceptionHandler(GenericErrorHandler errorHandler) {
        this.errorHandler = errorHandler;
    }

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException {
        errorHandler.respond(response, UNAUTHORIZED, SERVER_LOGIN_FAILED_ERROR);
    }
}
