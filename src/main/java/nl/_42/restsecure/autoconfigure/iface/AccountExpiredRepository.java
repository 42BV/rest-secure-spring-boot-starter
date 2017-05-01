package nl._42.restsecure.autoconfigure.iface;

public interface AccountExpiredRepository {

    <T extends RegisteredUser> boolean isAccountNonExpired(T user);
}
