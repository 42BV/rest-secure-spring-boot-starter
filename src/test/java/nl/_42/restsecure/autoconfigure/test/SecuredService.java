package nl._42.restsecure.autoconfigure.test;

import org.springframework.security.access.prepost.PreAuthorize;

public class SecuredService {

    public boolean everybody() {
        return true;
    }

    @PreAuthorize("isAuthenticated()")
    public boolean authenticated() {
        return true;
    }

    @PreAuthorize("hasRole('admin')")
    public boolean admin() {
        return true;
    }
}
