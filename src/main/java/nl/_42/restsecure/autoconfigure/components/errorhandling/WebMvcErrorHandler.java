package nl._42.restsecure.autoconfigure.components.errorhandling;

import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * Default error handler that handles {@link AccessDeniedException} thrown when a method security check fails.
 * Sets the http response status to 401 and returns json in the body: { errorCode: 'SERVER.ACCESS_DENIED_ERROR' }
 * 
 * This error handler has an {@link Order} annotation set with priority 0 to make sure that it will catch exceptions before any other
 * exception handler with default order does.
 * 
 * If you want to handle method security exeptions yourself, you must annotate an errorhandler with {@link Order} with priority <i>less than zero</i> .
 */
@RestControllerAdvice
@Order(0)
public class WebMvcErrorHandler {

    public static final String SERVER_ACCESS_DENIED_ERROR = "SERVER.ACCESS_DENIED_ERROR";
    
    @ExceptionHandler(AccessDeniedException.class)
    @ResponseStatus(HttpStatus.FORBIDDEN)
    public GenericErrorResult handlesAccessDeniedException() {
        return new GenericErrorResult(SERVER_ACCESS_DENIED_ERROR);
    }

}
