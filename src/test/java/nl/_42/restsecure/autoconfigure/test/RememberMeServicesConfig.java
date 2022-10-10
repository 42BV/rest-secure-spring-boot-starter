package nl._42.restsecure.autoconfigure.test;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.RememberMeServices;

@Configuration
public class RememberMeServicesConfig {

    public static final String REMEMBER_ME_HEADER = "RememberMe";

    @Bean
    public RememberMeServices rememberMeServices() {
        return new RememberMeServices() {

            @Override
            public Authentication autoLogin(HttpServletRequest request, HttpServletResponse response) {
                return null;
            }

            @Override
            public void loginFail(HttpServletRequest request, HttpServletResponse response) {
                response.addHeader(REMEMBER_ME_HEADER, "failed");
            }

            @Override
            public void loginSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
                response.addHeader(REMEMBER_ME_HEADER, "success");
            }

        };
    }

}
