package nl._42.restsecure.autoconfigure.iface;

public interface AccountExpiredRepository<T> {

    boolean isAccountNonExpired(T user);
}
