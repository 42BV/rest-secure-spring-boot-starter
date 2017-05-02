package nl._42.restsecure.autoconfigure.iface;

public interface CredentialsExpiredRepository<T> {

    boolean isCredentialsNonExpired(T user);
}
