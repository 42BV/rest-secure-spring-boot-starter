package nl._42.restsecure.autoconfigure.authentication;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

class UserDetailServiceTest {

    private InMemoryUserDetailService service;

    @BeforeEach
    void setUp() {
        service = new InMemoryUserDetailService();
    }

    @Test
    void loadUserByUsername_shouldSucceed() {
        User user = new User("henk", "admin");

        service.register(user);

        UserDetailsAdapter<User> details = service.loadUserByUsername("henk");
        assertEquals(user, details.user());
    }

    @Test
    void loadUserByUsername_unknownUser_shouldFail() {
        Assertions.assertThrows(UsernameNotFoundException.class, () -> service.loadUserByUsername("unknown"));
    }

}
