package nl._42.restsecure.autoconfigure.iface;

public interface AccountLockedRepository {

    <T extends RegisteredUser> boolean isAccountNonLocked(T user);
}
