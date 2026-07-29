package nl._42.restsecure.autoconfigure.errorhandling;

import static nl._42.restsecure.autoconfigure.errorhandling.RestAccessDeniedHandler.SERVER_ACCESS_DENIED_ERROR;
import static nl._42.restsecure.autoconfigure.errorhandling.RestAccessDeniedHandler.SERVER_AUTHENTICATE_ERROR;
import static nl._42.restsecure.autoconfigure.errorhandling.RestAccessDeniedHandler.SERVER_SESSION_INVALID_ERROR;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.HttpStatus.UNAUTHORIZED;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * Default error handler that handles {@link AccessDeniedException} thrown when a method security check fails.
 * Mirrors the behavior of {@link RestAccessDeniedHandler}: when the current user is fully authenticated, the http response status is set to 403 with
 * RFC-7807 json in the body with a custom property: { errorCode: 'SERVER.ACCESS_DENIED_ERROR' }. When the current user is not fully authenticated
 * (anonymous or remember-me), the http response status is set to 401 with errorCode 'SERVER.AUTHENTICATE_ERROR', or 'SERVER.SESSION_TIMEOUT_ERROR'
 * when the session of the request is no longer valid.
 * This error handler has an {@link Order} annotation set with priority 0 to make sure that it will catch exceptions before any other
 * exception handler with default order does.
 * If you want to handle method security exeptions yourself, you must annotate an errorhandler with {@link Order} with priority <i>less than zero</i> .
 */
@RestControllerAdvice
@Order(0)
public class WebMvcErrorHandler {

    private final AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();

    @ExceptionHandler(AccessDeniedException.class)
    public ProblemDetail handlesAccessDeniedException(HttpServletRequest request, AccessDeniedException ex) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (trustResolver.isFullyAuthenticated(authentication)) {
            return problemDetail(FORBIDDEN, SERVER_ACCESS_DENIED_ERROR, ex);
        }
        String errorCode = request.isRequestedSessionIdValid()
                ? SERVER_AUTHENTICATE_ERROR
                : SERVER_SESSION_INVALID_ERROR;
        return problemDetail(UNAUTHORIZED, errorCode, ex);
    }

    private ProblemDetail problemDetail(HttpStatus status, String errorCode, AccessDeniedException ex) {
        ProblemDetail pd = ProblemDetail.forStatusAndDetail(status, ex.getMessage());
        pd.setProperty("errorCode", errorCode);
        return pd;
    }

}
