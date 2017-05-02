package nl._42.restsecure.autoconfigure.iface;

public interface UserEnabledResolver<T extends RegisteredUser> {

    boolean isEnabled(T user);
}
