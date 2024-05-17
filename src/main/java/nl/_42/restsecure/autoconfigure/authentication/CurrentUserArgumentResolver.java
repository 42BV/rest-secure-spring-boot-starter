package nl._42.restsecure.autoconfigure.authentication;

import java.util.Objects;
import java.util.Optional;

import org.springframework.core.MethodParameter;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

public final class CurrentUserArgumentResolver implements HandlerMethodArgumentResolver {

    private final UserResolver<RegisteredUser> userResolver;

    public CurrentUserArgumentResolver(UserResolver<RegisteredUser> userResolver) {
        this.userResolver = userResolver;
    }

    @Override
    public boolean supportsParameter(MethodParameter parameter) {
        return AnnotationUtils.getAnnotation(parameter.getParameter(), CurrentUser.class) != null;
    }

    @Override
    public RegisteredUser resolveArgument(MethodParameter parameter, ModelAndViewContainer container, NativeWebRequest webRequest,
            WebDataBinderFactory binderFactory) {
        CurrentUser annotation = AnnotationUtils.getAnnotation(parameter.getParameter(), CurrentUser.class);
        Objects.requireNonNull(annotation, "Mapping must be annotated with the @CurrentUser annotation");

        Optional<RegisteredUser> user = userResolver.resolve();
        if (annotation.required()) {
            return user.orElseThrow(() -> new IllegalStateException("No current user found"));
        }

        return user.orElse(null);
    }

}
