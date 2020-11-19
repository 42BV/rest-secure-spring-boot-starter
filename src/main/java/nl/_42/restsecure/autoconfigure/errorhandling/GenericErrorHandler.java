package nl._42.restsecure.autoconfigure.errorhandling;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

import java.io.IOException;

import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * REST errorhandler that sets given http status and writes given errorCode as json object to the http response.
 * Json example: { errorCode: 'server.error'}
 */
@Component
public class GenericErrorHandler {

    private final ObjectMapper objectMapper;

    public GenericErrorHandler(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public void respond(HttpServletResponse response, HttpStatus status, String errorCode) throws IOException {
        response.setStatus(status.value());
        response.setContentType(APPLICATION_JSON_VALUE);
        objectMapper.writeValue(response.getWriter(), new GenericErrorResult(errorCode));
        response.getWriter().flush();
    }
}
