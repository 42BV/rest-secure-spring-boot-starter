package nl._42.restsecure.autoconfigure.userdetails;

public interface AccountLockedResolver<T extends RegisteredUser> {

    boolean isAccountNonLocked(T user);
}
