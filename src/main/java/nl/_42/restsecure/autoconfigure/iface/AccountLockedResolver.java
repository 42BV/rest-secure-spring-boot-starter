package nl._42.restsecure.autoconfigure.iface;

public interface AccountLockedResolver<T extends RegisteredUser> {

    boolean isAccountNonLocked(T user);
}
