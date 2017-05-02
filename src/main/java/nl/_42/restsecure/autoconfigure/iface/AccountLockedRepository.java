package nl._42.restsecure.autoconfigure.iface;

public interface AccountLockedRepository<T> {

    boolean isAccountNonLocked(T user);
}
