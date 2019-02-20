package nl._42.restsecure.autoconfigure.authentication;

import org.springframework.security.test.context.support.WithSecurityContext;

import java.lang.annotation.*;

@Target({ ElementType.METHOD, ElementType.TYPE })
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
@WithSecurityContext(factory = WithUserSecurityContextFactory.class)
public @interface WithUser {

    /**
     * Specifies the username.
     * @return
     */
    String value();

}
