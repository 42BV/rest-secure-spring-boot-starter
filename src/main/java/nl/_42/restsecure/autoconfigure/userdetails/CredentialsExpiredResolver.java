package nl._42.restsecure.autoconfigure.userdetails;

public interface CredentialsExpiredResolver<T extends RegisteredUser> {

    boolean isCredentialsNonExpired(T user);
}
