package nl._42.restsecure.autoconfigure;

import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.HttpStatus.UNAUTHORIZED;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import nl._42.restsecure.autoconfigure.components.errorhandling.GenericErrorHandler;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;

/**
 * Handles all authentication- and authorization exceptions that can occur in the http web environment. 
 */
class RestAccessDeniedHandler implements AccessDeniedHandler, AuthenticationEntryPoint {

    public static final String SERVER_AUTHENTICATE_ERROR = "SERVER.AUTHENTICATE_ERROR";
    public static final String SERVER_ACCESS_DENIED_ERROR = "SERVER.ACCESS_DENIED_ERROR";
    public static final String SERVER_SESSION_INVALID_ERROR = "SERVER.SESSION_TIMEOUT_ERROR";
    
    private final GenericErrorHandler errorHandler;

    RestAccessDeniedHandler(GenericErrorHandler errorHandler) {
        this.errorHandler = errorHandler;
    }

    /**
     * Handles URL authority matching failures.
     * {@inheritDoc}
     */
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException ex) throws IOException, ServletException {
        errorHandler.respond(response, FORBIDDEN, SERVER_ACCESS_DENIED_ERROR);
    }

    /**
     * Handles authentication exception when trying to reach a restricted URL
     * {@inheritDoc}
     */
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException ex) throws IOException, ServletException {
        String errorCode = SERVER_AUTHENTICATE_ERROR;
        if (request.getRequestedSessionId() != null
                && !request.isRequestedSessionIdValid()) {
            errorCode = SERVER_SESSION_INVALID_ERROR;
        }
        errorHandler.respond(response, UNAUTHORIZED, errorCode);
    }
}