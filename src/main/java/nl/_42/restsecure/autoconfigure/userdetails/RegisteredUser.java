package nl._42.restsecure.autoconfigure.userdetails;

import java.util.List;

public interface RegisteredUser {

    String getUsername();
    
    String getPassword();
    
    List<String> getRolesAsString();
}
