package nl._42.restsecure.autoconfigure.userdetails;

public interface AccountExpiredResolver<T extends RegisteredUser> {

    boolean isAccountNonExpired(T user);
}
