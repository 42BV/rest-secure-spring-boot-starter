package nl._42.restsecure.autoconfigure.authentication;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Use this annotation on a controller method parameter to resolve the current logged in user.
 * Type of this parameter must be your custom user type implementing {@link RegisteredUser}.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target({ ElementType.PARAMETER, ElementType.ANNOTATION_TYPE })
public @interface CurrentUser {

    /**
     * Is the current user required, or can the user also be {@code null}.
     * When required, the resolver will throw an exception if no user is found.
     * @return is required
     */
    boolean required() default true;

}
