package nl._42.restsecure.autoconfigure;

import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.HttpStatus.UNAUTHORIZED;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.csrf.MissingCsrfTokenException;

import nl._42.restsecure.autoconfigure.components.errorhandling.GenericErrorHandler;

/**
 * Handles all authentication- and authorization exceptions that can occur in the http web environment. 
 */
class RestAccessDeniedHandler implements AccessDeniedHandler, AuthenticationEntryPoint {

    private static final String SERVER_AUTHENTICATE_ERROR = "SERVER.AUTHENTICATE_ERROR";
    private static final String SERVER_SESSION_TIMEOUT_ERROR = "SERVER.SESSION_TIMEOUT_ERROR";
    private static final String SERVER_ACCESS_DENIED_ERROR = "SERVER.ACCESS_DENIED_ERROR";

    private final GenericErrorHandler errorHandler;

    RestAccessDeniedHandler(GenericErrorHandler errorHandler) {
        this.errorHandler = errorHandler;
    }

    /**
     * Handles CSRF- and URL authority matching failures.
     * {@inheritDoc}
     */
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException ex) throws IOException, ServletException {
        if (ex instanceof MissingCsrfTokenException) {
            errorHandler.respond(response, UNAUTHORIZED, SERVER_SESSION_TIMEOUT_ERROR);
        } else {
            errorHandler.respond(response, FORBIDDEN, SERVER_ACCESS_DENIED_ERROR);
        }
    }

    /**
     * Handles authentication exception when trying to reach a restricted URL
     * {@inheritDoc}
     */
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException ex) throws IOException, ServletException {
        errorHandler.respond(response, UNAUTHORIZED, SERVER_AUTHENTICATE_ERROR);
    }
}