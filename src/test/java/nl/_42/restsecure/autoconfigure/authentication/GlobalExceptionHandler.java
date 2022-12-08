package nl._42.restsecure.autoconfigure.authentication;

import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import javax.servlet.http.HttpServletResponse;
import java.util.Map;

import static org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR;

@ControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(RuntimeException.class)
    public Map<String, String> handleRuntimeException(RuntimeException exception, HttpServletResponse response) {
        response.setStatus(INTERNAL_SERVER_ERROR.value());
        return error(exception);
    }

    private static Map<String, String> error(Throwable throwable) {
        return Map.of("error", throwable.getMessage());
    }

}
