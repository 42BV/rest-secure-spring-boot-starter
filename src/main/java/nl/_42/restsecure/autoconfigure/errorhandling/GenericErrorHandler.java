package nl._42.restsecure.autoconfigure.errorhandling;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

import java.io.IOException;

import jakarta.servlet.http.HttpServletResponse;
import tools.jackson.databind.ObjectMapper;

import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.stereotype.Component;

/**
 * REST errorhandler that sets given http status and writes given errorCode as custom property in the RFC-7078 json object to the http response.
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
        ProblemDetail pd = ProblemDetail.forStatus(status);
        pd.setProperty("errorCode", errorCode);
        objectMapper.writeValue(response.getWriter(), pd);
        response.getWriter().flush();
    }
}
