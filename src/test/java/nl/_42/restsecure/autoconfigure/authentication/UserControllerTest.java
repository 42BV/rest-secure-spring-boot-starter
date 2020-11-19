package nl._42.restsecure.autoconfigure.authentication;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import nl._42.restsecure.autoconfigure.AbstractApplicationContextTest;
import nl._42.restsecure.autoconfigure.test.ActiveUserConfig;

import org.junit.jupiter.api.Test;

public class UserControllerTest extends AbstractApplicationContextTest {

    @Test
    public void me_shouldSucceed_whenLoggedIn() throws Exception {
        getWebClient(ActiveUserConfig.class)
            .perform(get("/users/me"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("authorities[0]").value("ROLE_ADMIN"))
            .andExpect(jsonPath("username").value("username"));
    }

}
