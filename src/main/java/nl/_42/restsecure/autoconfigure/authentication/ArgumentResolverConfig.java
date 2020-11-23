package nl._42.restsecure.autoconfigure.authentication;

import java.util.List;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class ArgumentResolverConfig implements WebMvcConfigurer {

    private final UserResolver<RegisteredUser> userResolver;

    public ArgumentResolverConfig(@Lazy UserResolver<RegisteredUser> userResolver) {
        this.userResolver = userResolver;
    }

    @Override
    public void addArgumentResolvers(List<HandlerMethodArgumentResolver> resolvers) {
        resolvers.add(new CurrentUserArgumentResolver(userResolver));
    }

}