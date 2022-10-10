package nl._42.restsecure.autoconfigure.authentication;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.core.MethodParameter;

class CurrentUserArgumentResolverTest {

    private final CurrentUserArgumentResolver resolver = new CurrentUserArgumentResolver(null);

    @Test
    void supports_true() {
        MethodParameter parameter = Mockito.mock(MethodParameter.class);
        CurrentUser annotation = Mockito.mock(CurrentUser.class);
        Mockito.when(parameter.getParameterAnnotation(CurrentUser.class)).thenReturn(annotation);

        assertTrue(resolver.supportsParameter(parameter));
    }

    @Test
    void supports_false() {
        MethodParameter parameter = Mockito.mock(MethodParameter.class);
        assertFalse(resolver.supportsParameter(parameter));
    }
}
