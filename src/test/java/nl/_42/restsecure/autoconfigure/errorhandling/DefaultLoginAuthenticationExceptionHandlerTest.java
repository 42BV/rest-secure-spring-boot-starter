package nl._42.restsecure.autoconfigure.errorhandling;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;

import nl._42.restsecure.autoconfigure.authentication.mfa.MfaAuthenticationProvider;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;

import com.fasterxml.jackson.databind.ObjectMapper;

class DefaultLoginAuthenticationExceptionHandlerTest {

    @Nested
    class handle {

        @Test
        @DisplayName("should return MFA_CODE_REQUIRED error for insufficient auth exception with mfa code required message")
        void shouldReturnMfaCodeRequiredError() throws IOException {
            DefaultLoginAuthenticationExceptionHandler handler = new DefaultLoginAuthenticationExceptionHandler(new GenericErrorHandler(new ObjectMapper()));

            MockHttpServletResponse response = new MockHttpServletResponse();
            handler.handle(new MockHttpServletRequest(), response,
                    new InsufficientAuthenticationException(MfaAuthenticationProvider.SERVER_MFA_CODE_REQUIRED_ERROR));

            assertEquals(HttpStatus.UNAUTHORIZED.value(), response.getStatus());
            assertEquals("{\"errorCode\":\"SERVER.MFA_CODE_REQUIRED_ERROR\"}", response.getContentAsString());
        }

        @Test
        @DisplayName("should return SERVER_LOGIN_FAILED_ERROR error for any other exception")
        void shouldReturnLoginFailedErrorForAnyOtherException() throws IOException {
            DefaultLoginAuthenticationExceptionHandler handler = new DefaultLoginAuthenticationExceptionHandler(new GenericErrorHandler(new ObjectMapper()));

            MockHttpServletResponse response1 = new MockHttpServletResponse();
            MockHttpServletResponse response2 = new MockHttpServletResponse();
            MockHttpServletResponse response3 = new MockHttpServletResponse();
            // Case 1 is the MFA case, but with exception class of another type (thus should not be picked up)
            handler.handle(new MockHttpServletRequest(), response1, new BadCredentialsException(MfaAuthenticationProvider.SERVER_MFA_CODE_REQUIRED_ERROR));
            handler.handle(new MockHttpServletRequest(), response2,
                    new BadCredentialsException(DefaultLoginAuthenticationExceptionHandler.SERVER_LOGIN_FAILED_ERROR));
            handler.handle(new MockHttpServletRequest(), response3, new BadCredentialsException("Invalid username or password"));

            assertEquals(HttpStatus.UNAUTHORIZED.value(), response1.getStatus());
            assertEquals(HttpStatus.UNAUTHORIZED.value(), response2.getStatus());
            assertEquals(HttpStatus.UNAUTHORIZED.value(), response3.getStatus());
            assertEquals("{\"errorCode\":\"SERVER.LOGIN_FAILED_ERROR\"}", response1.getContentAsString());
            assertEquals("{\"errorCode\":\"SERVER.LOGIN_FAILED_ERROR\"}", response2.getContentAsString());
            assertEquals("{\"errorCode\":\"SERVER.LOGIN_FAILED_ERROR\"}", response3.getContentAsString());
        }

    }
}
