package nl._42.restsecure.autoconfigure.errorhandling;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/test")
public class TestController {
    
    @PreAuthorize("hasRole('ROLE_UNKNOWN')")
    @GetMapping("/preauthorized")
    /**
     * Empty REST endpoint for @PreAuthorize testing.
     */
    public void restrictedMethod() {
        // Intentionally left without implementation because the test will never reach this.
    }

}
