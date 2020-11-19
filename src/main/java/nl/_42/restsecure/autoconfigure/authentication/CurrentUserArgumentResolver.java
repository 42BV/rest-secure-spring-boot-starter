package nl._42.restsecure.autoconfigure.authentication;

import org.springframework.core.MethodParameter;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

public final class CurrentUserArgumentResolver implements HandlerMethodArgumentResolver {

  private final UserResolver<RegisteredUser> userResolver;

  public CurrentUserArgumentResolver(UserResolver userResolver) {
    this.userResolver = userResolver;
  }

  @Override
  public boolean supportsParameter(MethodParameter parameter) {
    return parameter.getParameterAnnotation(CurrentUser.class) != null;
  }

  @Override
  public RegisteredUser resolveArgument(MethodParameter parameter, ModelAndViewContainer container, NativeWebRequest webRequest, WebDataBinderFactory binderFactory) {
    return userResolver.resolve().orElseThrow(IllegalStateException::new);
  }

}
