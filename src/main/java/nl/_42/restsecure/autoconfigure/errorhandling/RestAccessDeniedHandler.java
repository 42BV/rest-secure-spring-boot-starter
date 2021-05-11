package nl._42.restsecure.autoconfigure.errorhandling;

import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.HttpStatus.UNAUTHORIZED;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

/**
 * Handles all authentication- and authorization exceptions that can occur in the http web environment. 
 */
@Component
public class RestAccessDeniedHandler implements AccessDeniedHandler, AuthenticationEntryPoint {

    public static final String SERVER_AUTHENTICATE_ERROR = "SERVER.AUTHENTICATE_ERROR";
    public static final String SERVER_ACCESS_DENIED_ERROR = "SERVER.ACCESS_DENIED_ERROR";
    public static final String SERVER_SESSION_INVALID_ERROR = "SERVER.SESSION_TIMEOUT_ERROR";
    
    private final GenericErrorHandler errorHandler;
    private final Logger log = LoggerFactory.getLogger(RestAccessDeniedHandler.class);

    @Autowired
    public RestAccessDeniedHandler(GenericErrorHandler handler) {
        this.errorHandler = handler;
    }

    /**
     * Handles URL authority matching failures.
     * {@inheritDoc}
     */
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException exception) throws IOException {
        LogUtil.logAuthenticationFailure(log, exception);
        errorHandler.respond(response, FORBIDDEN, SERVER_ACCESS_DENIED_ERROR);
    }

    /**
     * Handles authentication exception when trying to reach a restricted URL.
     * {@inheritDoc}
     */
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException {
        LogUtil.logAuthenticationFailure(log, exception);
        String errorCode = request.isRequestedSessionIdValid()
                ? SERVER_AUTHENTICATE_ERROR
                : SERVER_SESSION_INVALID_ERROR;
        errorHandler.respond(response, UNAUTHORIZED, errorCode);
    }
}
