package nl._42.restsecure.autoconfigure.shared.test;

import static nl._42.restsecure.autoconfigure.shared.test.config.UserDetailsServiceConfig.createUser;
import static org.springframework.boot.test.util.EnvironmentTestUtils.addEnvironment;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.setup.MockMvcBuilders.webAppContextSetup;

import nl._42.restsecure.autoconfigure.WebSecurityAutoConfig;
import nl._42.restsecure.autoconfigure.userdetails.RegisteredUser;
import nl._42.restsecure.autoconfigure.userdetails.UserDetailsAdapter;

import org.junit.After;
import org.springframework.boot.autoconfigure.jackson.JacksonAutoConfiguration;
import org.springframework.boot.autoconfigure.web.HttpMessageConvertersAutoConfiguration;
import org.springframework.boot.autoconfigure.web.WebMvcAutoConfiguration;
import org.springframework.mock.web.MockServletContext;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;

public class AbstractApplicationContextTest {

    protected AnnotationConfigWebApplicationContext context;
    
    @After
    public void tearDown() {
        if (this.context != null) {
            this.context.close();
        }
    }
    
    protected MockMvc getWebClient(Class<?>... appConfig) {
        loadApplicationContext(appConfig);
        return webAppContextSetup(context)
            .apply(springSecurity())
            .defaultRequest(get("/")
                .contentType(APPLICATION_JSON)
                .with(csrf())
                .with(user(new UserDetailsAdapter<RegisteredUser>(createUser()))))
            .alwaysDo(print())
            .build();
    }
   
    protected void loadApplicationContext() {
        this.context = load(create());
    }
    
    protected void loadApplicationContext(String... env) {
        this.context = load(create(env));
    }

    protected void loadApplicationContext(Class<?>... config) {
        AnnotationConfigWebApplicationContext appContext = create();
        appContext.register(config);
        this.context = load(appContext);
    }
    
    private AnnotationConfigWebApplicationContext create(String... env) {
        AnnotationConfigWebApplicationContext applicationContext = new AnnotationConfigWebApplicationContext();
        addEnvironment(applicationContext, env);
        return applicationContext;
    }
    
    private AnnotationConfigWebApplicationContext load(AnnotationConfigWebApplicationContext applicationContext) {
        applicationContext.register(
                WebMvcAutoConfiguration.class,
                JacksonAutoConfiguration.class,
                HttpMessageConvertersAutoConfiguration.class,
                WebSecurityAutoConfig.class);
        applicationContext.setServletContext(new MockServletContext());
        applicationContext.refresh();
        return applicationContext;
    }
}
