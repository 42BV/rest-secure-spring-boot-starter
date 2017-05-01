package nl._42.restsecure.autoconfigure.iface;

public interface CredentialsExpiredRepository {

    <T extends RegisteredUser> boolean isCredentialsNonExpired(T user);
}
