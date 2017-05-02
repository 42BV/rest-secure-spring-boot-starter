package nl._42.restsecure.autoconfigure.iface;

public interface AccountExpiredResolver<T extends RegisteredUser> {

    boolean isAccountNonExpired(T user);
}
