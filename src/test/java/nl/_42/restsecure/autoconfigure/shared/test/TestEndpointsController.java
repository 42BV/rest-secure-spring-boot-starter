package nl._42.restsecure.autoconfigure.shared.test;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/test")
public class TestEndpointsController {

    @GetMapping("/forbidden")
    public void forbidden() {
        
    }
    
}