package nl._42.restsecure.autoconfigure.authentication;

import org.junit.jupiter.api.Test;
import org.springframework.core.MethodParameter;

import java.lang.reflect.Method;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CurrentUserArgumentResolverTest {

    private final CurrentUserArgumentResolver resolver = new CurrentUserArgumentResolver(null);

    @Test
    void supports_true() throws NoSuchMethodException {
        Method method = MyController.class.getMethod("annotated", RegisteredUser.class);
        MethodParameter parameter = new MethodParameter(method, 0);

        assertTrue(resolver.supportsParameter(parameter));
    }

    @Test
    void supports_false() throws NoSuchMethodException {
        Method method = MyController.class.getMethod("none", RegisteredUser.class);
        MethodParameter parameter = new MethodParameter(method, 0);

        assertFalse(resolver.supportsParameter(parameter));
    }

    public static class MyController {

        public RegisteredUser annotated(@CurrentUser RegisteredUser user) {
            return user;
        }

        public RegisteredUser none(RegisteredUser user) {
            return user;
        }

    }

}
