package nl._42.restsecure.autoconfigure.userdetails;

public interface UserEnabledResolver<T extends RegisteredUser> {

    boolean isEnabled(T user);
}
