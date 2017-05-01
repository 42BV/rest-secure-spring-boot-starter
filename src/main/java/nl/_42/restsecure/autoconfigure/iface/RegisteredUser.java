package nl._42.restsecure.autoconfigure.iface;

import java.util.List;

public interface RegisteredUser {

    String getUsername();
    
    String getPassword();
    
    List<String> getRoles();
}
