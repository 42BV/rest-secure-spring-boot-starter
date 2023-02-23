package nl._42.restsecure.autoconfigure.errorhandling;

import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.HttpStatus.UNAUTHORIZED;

import java.io.IOException;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import lombok.extern.slf4j.Slf4j;
import nl._42.restsecure.autoconfigure.form.FormValues;
import nl._42.restsecure.autoconfigure.form.LoginForm;
import nl._42.restsecure.autoconfigure.utils.FormUtil;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

/**
 * Handles all authentication- and authorization exceptions that can occur in the http web environment.
 */
@Slf4j
@Component
public class RestAccessDeniedHandler implements AccessDeniedHandler, AuthenticationEntryPoint {

    public static final String SERVER_AUTHENTICATE_ERROR = "SERVER.AUTHENTICATE_ERROR";
    public static final String SERVER_ACCESS_DENIED_ERROR = "SERVER.ACCESS_DENIED_ERROR";
    public static final String SERVER_SESSION_INVALID_ERROR = "SERVER.SESSION_TIMEOUT_ERROR";

    private final GenericErrorHandler errorHandler;

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
        FormValues<LoginForm> formValues = FormUtil.getFormFromRequest(request, LoginForm.class);
        LogUtil.logAuthenticationFailure(log, formValues.form(), exception);
        errorHandler.respond(response, FORBIDDEN, SERVER_ACCESS_DENIED_ERROR);
    }

    /**
     * Handles authentication exception when trying to reach a restricted URL.
     * {@inheritDoc}
     */
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException {
        FormValues<LoginForm> formValues = FormUtil.getFormFromRequest(request, LoginForm.class);
        LogUtil.logAuthenticationFailure(log, formValues.form(), exception);
        String errorCode = request.isRequestedSessionIdValid()
                ? SERVER_AUTHENTICATE_ERROR
                : SERVER_SESSION_INVALID_ERROR;
        errorHandler.respond(response, UNAUTHORIZED, errorCode);
    }
}
