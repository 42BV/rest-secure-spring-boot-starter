package nl._42.restsecure.autoconfigure.authentication;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import nl._42.restsecure.autoconfigure.userdetails.RegisteredUser;

import org.springframework.security.core.annotation.AuthenticationPrincipal;

/**
 * Use this annotation on a controller method parameter to resolve the current logged in user.
 * Type of this parameter must be your custom user type implementing {@link RegisteredUser}.
 */
@Target(ElementType.PARAMETER)
@Retention(RetentionPolicy.RUNTIME)
@AuthenticationPrincipal(errorOnInvalidType = true, expression = "user")
public @interface CurrentUser {

}
