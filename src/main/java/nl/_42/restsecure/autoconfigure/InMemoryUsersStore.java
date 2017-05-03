package nl._42.restsecure.autoconfigure;

import java.util.List;

import nl._42.restsecure.autoconfigure.userdetails.RegisteredUser;

public interface InMemoryUsersStore {

    List<RegisteredUser> users();
}
