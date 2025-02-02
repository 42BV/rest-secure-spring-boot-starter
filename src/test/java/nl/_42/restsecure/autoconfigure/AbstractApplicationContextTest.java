package nl._42.restsecure.autoconfigure;

import static nl._42.restsecure.autoconfigure.test.AbstractUserDetailsServiceConfig.RegisteredUserBuilder.user;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.log;
import static org.springframework.test.web.servlet.setup.MockMvcBuilders.webAppContextSetup;

import dev.samstevens.totp.spring.autoconfigure.TotpAutoConfiguration;
import nl._42.restsecure.autoconfigure.authentication.ArgumentResolverConfig;
import nl._42.restsecure.autoconfigure.authentication.RegisteredUser;
import nl._42.restsecure.autoconfigure.authentication.UserDetailsAdapter;

import org.junit.jupiter.api.AfterEach;
import org.springframework.boot.autoconfigure.http.HttpMessageConvertersAutoConfiguration;
import org.springframework.boot.autoconfigure.jackson.JacksonAutoConfiguration;
import org.springframework.boot.autoconfigure.web.servlet.WebMvcAutoConfiguration;
import org.springframework.mock.web.MockServletContext;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;

public abstract class AbstractApplicationContextTest {

    protected AnnotationConfigWebApplicationContext context;

    @AfterEach
    public void tearDown() {
        if (this.context != null) {
            this.context.close();
        }
    }

    protected MockMvc getWebClient(Class<?>... appConfig) {
        return webClient(user().build(), appConfig);
    }

    protected MockMvc getWebClientWithoutUser(Class<?>... appConfig) {
        return webClient(null, appConfig);
    }

    private MockMvc webClient(RegisteredUser defaultUser, Class<?>... appConfig) {
        loadApplicationContext(appConfig);
        MockHttpServletRequestBuilder defaultRequest = get("/")
                .contentType(APPLICATION_JSON)
                .with(csrf());
        if (defaultUser != null) defaultRequest.with(user(new UserDetailsAdapter<>(defaultUser)));
        return webAppContextSetup(context)
                .apply(springSecurity())
                .defaultRequest(defaultRequest)
                .alwaysDo(log())
                .build();
    }

    protected void loadApplicationContext(Class<?>... config) {
        AnnotationConfigWebApplicationContext appContext = new AnnotationConfigWebApplicationContext();
        appContext.register(config);
        this.context = load(appContext);
    }

    private AnnotationConfigWebApplicationContext load(AnnotationConfigWebApplicationContext applicationContext) {
        applicationContext.register(
                WebMvcAutoConfiguration.class,
                JacksonAutoConfiguration.class,
                HttpMessageConvertersAutoConfiguration.class,
                WebSecurityAutoConfig.class,
                ArgumentResolverConfig.class,
                TotpAutoConfiguration.class,
                MfaSecurityAutoConfig.class);

        applicationContext.setServletContext(new MockServletContext());
        applicationContext.refresh();
        return applicationContext;
    }
}
