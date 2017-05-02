package nl._42.restsecure.autoconfigure.iface;

public interface CredentialsExpiredResolver<T extends RegisteredUser> {

    boolean isCredentialsNonExpired(T user);
}
