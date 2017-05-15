package nl._42.restsecure.autoconfigure;

import java.util.List;

import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;

import nl._42.restsecure.autoconfigure.userdetails.RegisteredUser;

/**
 * Implement this interface and add it as {@link Bean} to the {@link ApplicationContext} to fill an in-memory authentication users store.
 */
public interface InMemoryUsersStore {

    /**
     * Returns all users with name and plaintext password to be loaded into the in memory authentication store.
     * @return List
     */
    List<RegisteredUser> users();
}
