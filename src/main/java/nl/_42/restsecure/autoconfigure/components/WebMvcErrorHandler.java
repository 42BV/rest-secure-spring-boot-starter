package nl._42.restsecure.autoconfigure.components;

import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;

@ControllerAdvice
@ResponseBody
public class WebMvcErrorHandler {

    public static final String SERVER_ACCESS_DENIED_ERROR = "SERVER.ACCESS_DENIED_ERROR";
    
    @ExceptionHandler(AccessDeniedException.class)
    @ResponseStatus(HttpStatus.FORBIDDEN)
    public GenericErrorResult handlesAccessDeniedException() {
        return new GenericErrorResult(SERVER_ACCESS_DENIED_ERROR);
    }
}
