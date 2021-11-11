package nl._42.restsecure.autoconfigure.authentication.mfa;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

class MfaExceptionTest {

    @Test
    void returnsMessageAndCause() {
        String message = "Oh no! Something went wrong!";
        Exception cause = new RuntimeException("Should never happen");
        MfaException exception = new MfaException(message, cause);
        assertEquals(message, exception.getMessage());
        assertEquals(cause, exception.getCause());
    }

}
