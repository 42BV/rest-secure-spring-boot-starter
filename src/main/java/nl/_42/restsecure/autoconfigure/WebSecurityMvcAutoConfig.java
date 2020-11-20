package nl._42.restsecure.autoconfigure;

import java.util.List;

import lombok.RequiredArgsConstructor;
import nl._42.restsecure.autoconfigure.authentication.CurrentUserArgumentResolver;
import nl._42.restsecure.autoconfigure.authentication.RegisteredUser;
import nl._42.restsecure.autoconfigure.authentication.UserResolver;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
@RequiredArgsConstructor
public class WebSecurityMvcAutoConfig implements WebMvcConfigurer {

    private final UserResolver<RegisteredUser> userResolver;

    @Override
    public void addArgumentResolvers(List<HandlerMethodArgumentResolver> resolvers) {
        resolvers.add(new CurrentUserArgumentResolver(userResolver));
    }

}