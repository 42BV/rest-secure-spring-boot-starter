package nl._42.restsecure.autoconfigure.authentication;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.core.MethodParameter;

public class CurrentUserArgumentResolverTest {

  private final CurrentUserArgumentResolver resolver = new CurrentUserArgumentResolver(null);

  @Test
  public void supports_true() {
    MethodParameter parameter = Mockito.mock(MethodParameter.class);
    CurrentUser annotation = Mockito.mock(CurrentUser.class);
    Mockito.when(parameter.getParameterAnnotation(CurrentUser.class)).thenReturn(annotation);

    assertEquals(true, resolver.supportsParameter(parameter));
  }

  @Test
  public void supports_false() {
    MethodParameter parameter = Mockito.mock(MethodParameter.class);

    assertEquals(false, resolver.supportsParameter(parameter));
  }

}
