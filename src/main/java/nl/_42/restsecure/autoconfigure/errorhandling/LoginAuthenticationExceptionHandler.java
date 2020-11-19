package nl._42.restsecure.autoconfigure.errorhandling;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.AuthenticationException;

public interface LoginAuthenticationExceptionHandler {

    void handle(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException;
}
