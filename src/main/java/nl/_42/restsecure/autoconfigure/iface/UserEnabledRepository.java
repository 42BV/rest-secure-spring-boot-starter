package nl._42.restsecure.autoconfigure.iface;

public interface UserEnabledRepository<T> {

    boolean isEnabled(T user);
}
