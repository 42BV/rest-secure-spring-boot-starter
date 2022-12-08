package nl._42.restsecure.autoconfigure.authentication;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/users")
public class UserController {

    @GetMapping("/me")
    public RegisteredUser me(@CurrentUser RegisteredUser user) {
        return user;
    }

    @GetMapping("/optional")
    public RegisteredUser optional(@CurrentUser(required = false) RegisteredUser user) {
        return user;
    }

    @GetMapping("/custom")
    public RegisteredUser custom(@OptionalUser RegisteredUser user) {
        return user;
    }

}
