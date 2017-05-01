package nl._42.restsecure.autoconfigure.iface;

public interface UserEnabledRepository {

    <T extends RegisteredUser> boolean isEnabled(T user);
}
