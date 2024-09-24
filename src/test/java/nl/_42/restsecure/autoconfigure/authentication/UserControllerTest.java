package nl._42.restsecure.autoconfigure.authentication;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Set;

import nl._42.restsecure.autoconfigure.AbstractApplicationContextTest;
import nl._42.restsecure.autoconfigure.test.ActiveUserConfig;

import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

class UserControllerTest extends AbstractApplicationContextTest {

    private static final Authentication NONE = new AnonymousAuthenticationToken("key", "none", Set.of(new SimpleGrantedAuthority("ROLE_NONE")));

    @Test
    void me_shouldSucceed_whenLoggedIn() throws Exception {
        getWebClient(ActiveUserConfig.class)
                .perform(get("/users/me"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("authorities[0]").value("ROLE_ADMIN"))
                .andExpect(jsonPath("username").value("username"));
    }

    @Test
    void me_shouldError_whenNotLoggedIn() throws Exception {
        getWebClient(ActiveUserConfig.class)
            .perform(get("/users/me")
                .with(authentication(NONE)))
            .andExpect(status().is5xxServerError())
            .andExpect(jsonPath("authorities").doesNotExist())
            .andExpect(jsonPath("username").doesNotExist());
    }

    @Test
    void optional_shouldSucceed_whenNotLoggedIn() throws Exception {
        getWebClient(ActiveUserConfig.class)
            .perform(get("/users/optional")
                .with(authentication(NONE)))
            .andExpect(status().isOk())
            .andExpect(jsonPath("authorities").doesNotExist())
            .andExpect(jsonPath("username").doesNotExist());
    }

    @Test
    void custom_shouldSucceed_whenNotLoggedIn() throws Exception {
        getWebClient(ActiveUserConfig.class)
            .perform(get("/users/custom")
                .with(authentication(NONE)))
            .andExpect(status().isOk())
            .andExpect(jsonPath("authorities").doesNotExist())
            .andExpect(jsonPath("username").doesNotExist());
    }
}
